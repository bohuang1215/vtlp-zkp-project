// 文件路径: ~/go/src/vtlp-zkp-project/main.go

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
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards" // [修复] 获取曲线ID常量
	"github.com/consensys/gnark-crypto/signature/eddsa"             // [修复] 恢复原版的签名库

	// --- Gnark ZKP 库 ---
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	// --- VTLP 协议库 ---
	"github.com/VTLP/protocol"

	// --- 本地模块 ---
	"vtlp.dev/m/circuit"
	"vtlp.dev/m/utils"
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
	fmt.Println("   面向时效性与数量限制的匿名数字凭证发行协议")
	fmt.Println("   阶段：端到端全流程集成 (VTLP + 全约束 ZKP)")
	fmt.Println("================================================================\n")

	// -----------------------------------------------------------------------
	// 阶段 0: 系统初始化
	// -----------------------------------------------------------------------
	fmt.Println("[Phase 0] 系统初始化...")

	fmt.Println("   -> 编译 ZKP 核心电路...")
	var myCircuit circuit.CredentialCircuit
	ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &myCircuit)
	if err != nil {
		log.Fatal("电路编译失败:", err)
	}
	fmt.Printf("   -> [!!!关键数据!!!] 当前电路总约束数量 (Constraints) 为: %d 条!\n", ccs.GetNbConstraints())

	fmt.Println("   -> 生成 ZKP 证明密钥 (Groth16 Setup)...")
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatal("Setup失败:", err)
	}

	fmt.Println("   -> 初始化 VTLP 全局参数...")
	rsaSetup := protocol.RSAExpSetup()

	fmt.Println("   -> 生成发行方签名密钥...")
	// [修复] 采用标准的 tedwards.BN254 常量生成 Baby Jubjub 上的密钥
	signKey, err := eddsa.New(tedwards.BN254, rand.Reader)
	if err != nil {
		log.Fatal("生成私钥失败:", err)
	}
	pubKey := signKey.Public()
	fmt.Println("   [完成] 系统参数准备就绪。\n")

	// -----------------------------------------------------------------------
	// 阶段 1: 凭证发行与锁定
	// -----------------------------------------------------------------------
	fmt.Println("[Phase 1] 凭证盲化发行与锁定...")

	secretVal := big.NewInt(12345)
	nullifierVal := big.NewInt(999)

	hFunc := mimc.NewMiMC()

	var secretFr, nullifierFr fr.Element
	secretFr.SetBigInt(secretVal)
	nullifierFr.SetBigInt(nullifierVal)
	bSec := secretFr.Bytes()
	bNull := nullifierFr.Bytes()

	hFunc.Write(bSec[:])
	hFunc.Write(bNull[:])
	commBytes := hFunc.Sum(nil)

	hFunc.Reset()
	hFunc.Write(bNull[:])
	snBytes := hFunc.Sum(nil)
	snVal := new(big.Int).SetBytes(snBytes)
	fmt.Printf("   -> [预计算] 防双花序列号 (SN): %s...\n", snVal.String()[:20])

	mockProofSet := make([][]byte, circuit.TreeDepth)
	mockHelper := make([][]byte, circuit.TreeDepth)
	currentHash := commBytes

	for i := 0; i < circuit.TreeDepth; i++ {
		var elemFr fr.Element
		elemFr.SetInt64(int64(100 + i))
		pathElement := elemFr.Bytes()

		mockProofSet[i] = pathElement[:]
		var zeroFr fr.Element
		zeroFr.SetInt64(0)
		zBytes := zeroFr.Bytes()
		mockHelper[i] = zBytes[:]

		hFunc.Reset()
		hFunc.Write(currentHash)
		hFunc.Write(pathElement[:])
		currentHash = hFunc.Sum(nil)
	}
	calculatedRoot := new(big.Int).SetBytes(currentHash)
	fmt.Printf("   -> [预计算] 合法 Merkle Root: %s...\n", calculatedRoot.String()[:20])

	hFunc.Reset()
	sigBytes, err := signKey.Sign(commBytes, hFunc)
	if err != nil {
		log.Fatal(err)
	}

	sigR := sigBytes[:32]
	sigS := sigBytes[32:]
	payloadTuple := utils.SecretTuple{
		SigR:       sigR,
		SigS:       sigS,
		ProofSet:   mockProofSet,
		PathHelper: mockHelper,
	}
	payloadBigInt, _ := utils.Serialize(payloadTuple)

	const T = 200000
	fmt.Printf("   -> 生成时间锁 (T=%d)...\n", T)
	seed, _ := rand.Int(rand.Reader, rsaSetup.RSAMod)
	key := protocol.GenPuzzle(seed, rsaSetup)
	ciphertext := XorBigInts(payloadBigInt, key)
	fmt.Println("   -> [锁定完成] 密文已下发。\n")

	// -----------------------------------------------------------------------
	// 阶段 2: 消费 - 解谜
	// -----------------------------------------------------------------------
	fmt.Println("[Phase 2] 用户本地解谜 (Time-Lock Solving)...")
	solveStart := time.Now()

	userKey := ManualSolve(seed, rsaSetup.RSAMod, T)
	recoveredPayloadBigInt := XorBigInts(ciphertext, userKey)

	fmt.Printf("   -> 解谜完成! 耗时: %s\n", time.Since(solveStart))

	recoveredTuple, err := utils.Deserialize(recoveredPayloadBigInt)
	if err != nil {
		log.Fatal("反序列化失败:", err)
	}
	fmt.Println("   -> [成功] 凭证见证恢复。\n")

	// -----------------------------------------------------------------------
	// 阶段 3: 消费 - 生成 ZKP
	// -----------------------------------------------------------------------
	fmt.Println("[Phase 3] 零知识证明生成 (ZKP Proving)...")
	proveStart := time.Now()

	var assignment circuit.CredentialCircuit
	assignment.Root = calculatedRoot
	assignment.SN = snVal
	// [修复] 在 v0.7.1 版本中，Assign 需要传入外层 SNARK 曲线的 ecc.ID
	assignment.Issuer.Assign(ecc.BN254, pubKey.Bytes())

	assignment.Secret = secretVal
	assignment.Nullifier = nullifierVal

	// [修复] 同样改为 ecc.BN254
	assignment.Sig.Assign(ecc.BN254, append(recoveredTuple.SigR, recoveredTuple.SigS...))

	var proofSetFr [circuit.TreeDepth]frontend.Variable
	var helperFr [circuit.TreeDepth]frontend.Variable
	recProofSet := utils.ConvertBytesToFr(recoveredTuple.ProofSet)
	recHelper := utils.ConvertBytesToFr(recoveredTuple.PathHelper)

	for i := 0; i < circuit.TreeDepth; i++ {
		proofSetFr[i] = recProofSet[i]
		helperFr[i] = recHelper[i]
	}
	assignment.PathElements = proofSetFr
	assignment.PathIndices = helperFr

	witness, _ := frontend.NewWitness(&assignment, ecc.BN254)

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Printf("   [错误] 证明生成失败: %v\n", err)
	} else {
		fmt.Printf("   -> [成功] 证明生成完毕! 耗时: %s\n", time.Since(proveStart))
	}

	// -----------------------------------------------------------------------
	// 阶段 4: 验证方核销
	// -----------------------------------------------------------------------
	if err == nil {
		fmt.Println("\n[Phase 4] 验证方核销 (Verification)...")
		verifyStart := time.Now()

		pubWitness, _ := witness.Public()
		err = groth16.Verify(proof, vk, pubWitness)
		if err != nil {
			log.Fatal("ZKP 验证失败:", err)
		}

		fmt.Printf("   -> (A) 哈希重构 & (B) 双花推导: 通过\n")
		fmt.Printf("   -> (C) Merkle 状态包含性: 通过\n")
		fmt.Printf("   -> (D) EdDSA 签名合法性: 通过\n")
		fmt.Printf("   -> [成功] 全约束 ZKP 验证极速通过! 验证耗时: %s\n", time.Since(verifyStart))
		fmt.Println("\n------------------------------------------------")
		fmt.Println("全链路跑通！理论设计与工程代码彻底闭环！")
	}
}
