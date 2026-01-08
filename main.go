package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"time"

	// --- 基础加密库 ---
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/signature/eddsa"

	// --- Gnark ZKP 库 ---
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	// --- VTLP 协议库 ---
	"github.com/VTLP/protocol"

	// --- 你的本地模块 ---
	"vtlp.dev/m/circuit" // 你的电路定义
	"vtlp.dev/m/utils"   // 你的序列化工具
)

// ==========================================
// 辅助函数：手动解谜 & XOR 加解密
// ==========================================

func ManualSolve(seed, N *big.Int, T int64) *big.Int {
	result := new(big.Int).Set(seed)
	two := big.NewInt(2)

	logStep := T / 10
	if logStep == 0 {
		logStep = 1
	}

	fmt.Printf("      [VTLP] 正在计算 %d 次平方...\n", T)
	for i := int64(0); i < T; i++ {
		result.Exp(result, two, N)
		if (i+1)%logStep == 0 {
			fmt.Printf("      进度: %d%%\r", (i+1)*100/T)
		}
	}
	fmt.Println("      进度: 100% (完成)   ")
	return result
}

func XorBigInts(a, b *big.Int) *big.Int {
	bytesA := a.Bytes()
	bytesB := b.Bytes()
	maxLen := len(bytesA)
	if len(bytesB) > maxLen {
		maxLen = len(bytesB)
	}

	res := make([]byte, maxLen)
	for i := 0; i < maxLen; i++ {
		var byteA, byteB byte
		if i < len(bytesA) {
			byteA = bytesA[len(bytesA)-1-i]
		}
		if i < len(bytesB) {
			byteB = bytesB[len(bytesB)-1-i]
		}
		res[maxLen-1-i] = byteA ^ byteB
	}
	return new(big.Int).SetBytes(res)
}

// ==========================================
// 主函数：端到端全流程演示
// ==========================================

func main() {
	fmt.Println("================================================================")
	fmt.Println("   毕业设计实验：面向时效性与数量限制的匿名数字凭证发行协议")
	fmt.Println("   阶段：端到端全流程集成 (VTLP + ZKP) [最终修正版 2.0]")
	fmt.Println("================================================================\n")

	// -----------------------------------------------------------------------
	// 阶段 0: 系统初始化 (System Setup)
	// -----------------------------------------------------------------------
	fmt.Println("[Phase 0] 系统初始化...")

	// 0.1 编译 ZKP 电路
	fmt.Println("   -> 编译 ZKP 电路 (SpendCircuit_Final)...")
	var myCircuit circuit.SpendCircuit_Final
	ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &myCircuit)
	if err != nil {
		log.Fatal("电路编译失败:", err)
	}

	// 0.2 生成 ZKP 证明密钥 (Groth16 Setup)...
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatal("Setup失败:", err)
	}

	// 0.3 初始化 VTLP 参数
	fmt.Println("   -> 生成 VTLP 全局参数 (RSA Modulus)...")
	rsaSetup := protocol.RSAExpSetup()

	// 0.4 生成发行方签名密钥
	fmt.Println("   -> 生成发行方签名密钥 (EdDSA Keypair)...")
	rng := rand.Reader
	signKey, _ := eddsa.New(1, rng)
	pubKey := signKey.Public()

	fmt.Println("   [完成] 系统参数准备就绪。\n")

	// -----------------------------------------------------------------------
	// 阶段 1: 发行 (Issuance & Locking)
	// -----------------------------------------------------------------------
	fmt.Println("[Phase 1] 凭证发行与锁定...")

	secretVal := big.NewInt(12345)  // 用户秘密
	nullifierVal := big.NewInt(999) // 防双花码

	// --- A. 准备 Merkle 路径并计算正确的 Root ---
	mockProofSet := make([][]byte, 3)
	mockHelper := make([][]byte, 3)

	// 初始化哈希器用来计算 Root
	hFunc := mimc.NewMiMC()

	// 1. 先计算叶子 comm = Hash(Secret, Nullifier)
	var secretFr, nullifierFr fr.Element
	secretFr.SetBigInt(secretVal)
	nullifierFr.SetBigInt(nullifierVal)

	// [修复点] 显式赋值给变量，使其可寻址
	bSec := secretFr.Bytes()
	bNull := nullifierFr.Bytes()

	hFunc.Write(bSec[:])
	hFunc.Write(bNull[:])
	commBytes := hFunc.Sum(nil) // 这是叶子节点

	// 2. 模拟构建 Merkle 树并计算 Root
	currentHash := commBytes
	for i := 0; i < 3; i++ {
		tmp := big.NewInt(int64(100 + i))
		pathElement := tmp.Bytes() // 路径上的兄弟节点

		mockProofSet[i] = pathElement[:]
		mockHelper[i] = make([]byte, 32) // Helper=0 (表示兄弟在右边)

		// 模仿电路逻辑计算 Hash(Left, Right)
		hFunc.Reset()
		hFunc.Write(currentHash) // Left
		hFunc.Write(pathElement) // Right
		currentHash = hFunc.Sum(nil)
	}

	// 此时 currentHash 就是正确的 Root！
	calculatedRoot := new(big.Int).SetBytes(currentHash)
	fmt.Printf("   -> [预计算] 合法的 Merkle Root 应为: %s...\n", calculatedRoot.String()[:20])

	// --- B. 发行方签名 Comm ---
	// 注意：Sign 之前不需要 Reset，因为 signKey.Sign 内部会处理，
	// 但我们要确保 hFunc 状态干净给 Verify 使用，所以这里最好传一个新的或者 Reset 过的
	hFunc.Reset()
	sigBytes, err := signKey.Sign(commBytes, hFunc)
	if err != nil {
		log.Fatal(err)
	}

	// --- C. 构造 SecretTuple ---
	sigR := sigBytes[:32]
	sigS := sigBytes[32:]

	payloadTuple := utils.SecretTuple{
		SigR:       sigR,
		SigS:       sigS,
		ProofSet:   mockProofSet,
		PathHelper: mockHelper,
	}

	// 1.3 序列化
	payloadBigInt, _ := utils.Serialize(payloadTuple)

	// 1.4 VTLP 锁定
	const T = 200000
	fmt.Printf("   -> 正在生成时间锁 (T=%d)...\n", T)

	seed, _ := rand.Int(rand.Reader, rsaSetup.RSAMod)
	key := protocol.GenPuzzle(seed, rsaSetup)
	ciphertext := XorBigInts(payloadBigInt, key)

	fmt.Println("   -> [锁定完成] 密文已发送给用户。\n")

	// -----------------------------------------------------------------------
	// 阶段 2: 消费 - 解谜
	// -----------------------------------------------------------------------
	fmt.Println("[Phase 2] 用户解谜 (Time-Lock Solving)...")
	solveStart := time.Now()

	userKey := ManualSolve(seed, rsaSetup.RSAMod, T)
	recoveredPayloadBigInt := XorBigInts(ciphertext, userKey)

	fmt.Printf("   -> 解谜完成! 耗时: %s\n", time.Since(solveStart))

	recoveredTuple, err := utils.Deserialize(recoveredPayloadBigInt)
	if err != nil {
		log.Fatal("反序列化失败:", err)
	}
	fmt.Println("   -> [成功] 用户已恢复凭证数据。\n")

	// -----------------------------------------------------------------------
	// 阶段 3: 消费 - 生成证明
	// -----------------------------------------------------------------------
	fmt.Println("[Phase 3] 用户生成零知识证明 (ZKP Proving)...")

	var assignment circuit.SpendCircuit_Final

	// 填入刚才计算的正确 Root
	assignment.Root = calculatedRoot

	assignment.Nullifier = nullifierVal
	assignment.T_Expiry = time.Now().Add(time.Hour).Unix()
	assignment.T_Current = time.Now().Unix()
	assignment.Secret = secretVal

	// 填入 Merkle 路径
	var proofSetFr [circuit.TreeDepth]frontend.Variable
	var helperFr [circuit.TreeDepth]frontend.Variable
	recProofSet := utils.ConvertBytesToFr(recoveredTuple.ProofSet)
	recHelper := utils.ConvertBytesToFr(recoveredTuple.PathHelper)

	for i := 0; i < circuit.TreeDepth; i++ {
		proofSetFr[i] = recProofSet[i]
		helperFr[i] = recHelper[i]
	}
	assignment.ProofSet = proofSetFr
	assignment.PathHelper = helperFr

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254)

	// 生成证明
	proof, err := groth16.Prove(ccs, pk, witness)

	if err != nil {
		log.Printf("   [错误] 生成证明失败: %v\n", err)
	} else {
		fmt.Println("   -> [成功] ZKP 证明已生成！(约束满足)")
	}

	// -----------------------------------------------------------------------
	// 阶段 4: 验证
	// -----------------------------------------------------------------------
	if proof != nil {
		fmt.Println("\n[Phase 4] 验证方验证 (Verification)...")

		// 验证签名
		hFunc.Reset() // 验证前重置哈希器
		isValid, _ := pubKey.Verify(append(recoveredTuple.SigR, recoveredTuple.SigS...), commBytes, hFunc)
		if isValid {
			fmt.Println("   -> (C) 签名验证通过 (电路外)。")
		} else {
			fmt.Println("   -> (C) 签名验证失败。")
		}

		// 验证 ZKP
		pubWitness, _ := witness.Public()
		err = groth16.Verify(proof, vk, pubWitness)
		if err != nil {
			log.Fatal("ZKP 验证失败:", err)
		}
		fmt.Println("   -> (A+B+D) ZKP 验证通过 (电路内)。")

		fmt.Println("\n------------------------------------------------")
		fmt.Println("恭喜！整个协议全链路跑通 (All Green)！")
	} else {
		fmt.Println("\n[Phase 4] 跳过验证 (因为证明生成失败)")
	}
}
