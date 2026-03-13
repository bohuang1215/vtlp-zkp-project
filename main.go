// 文件路径: ~/go/src/vtlp-zkp-project/main.go

package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"time"

	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"io"
	"os"

	// --- 基础加密库 ---
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/signature/eddsa"

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
// 辅助函数：手动解谜 & AES-GCM 加解密
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

func AESGCMEncrypt(y *big.Int, plaintext []byte) []byte {
	hash := sha256.Sum256(y.Bytes())
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		log.Fatal("AES 初始化失败:", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal("GCM 初始化失败:", err)
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal("生成 Nonce 失败:", err)
	}
	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext
}

func AESGCMDecrypt(y *big.Int, ciphertext []byte) []byte {
	hash := sha256.Sum256(y.Bytes())
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		log.Fatal("AES 初始化失败:", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal("GCM 初始化失败:", err)
	}
	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		log.Fatal("密文长度异常")
	}
	nonce, cipherData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesgcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		log.Fatal("AES-GCM 解密失败 (密钥错误或数据被篡改):", err)
	}
	return plaintext
}

// ==========================================
// 主函数：端到端全流程演示
// ==========================================

func main() {
	fmt.Println("================================================================")
	fmt.Println("   面向时效性与数量限制的匿名数字凭证发行协议")
	fmt.Println("   阶段：系统架构演进 (AES-GCM 引入与 100% 物理硬盘持久化)")
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

	// [硬核工程修复]：引入 bufio 并强制 WriteRawTo（未压缩序列化），彻底粉碎老版本库的椭圆曲线解压 Bug！
	fmt.Println("   -> [System] 正在将巨型证明密钥落盘 (无损未压缩持久化)...")

	pkFile, err := os.Create("proving.key")
	if err != nil {
		log.Fatal(err)
	}
	bwPK := bufio.NewWriter(pkFile)
	if rawPK, ok := pk.(interface {
		WriteRawTo(io.Writer) (int64, error)
	}); ok {
		rawPK.WriteRawTo(bwPK) // 接口断言：强制写入 X 和 Y 坐标
	} else {
		pk.WriteTo(bwPK)
	}
	bwPK.Flush()
	pkFile.Close()

	vkFile, err := os.Create("verifying.key")
	if err != nil {
		log.Fatal(err)
	}
	bwVK := bufio.NewWriter(vkFile)
	if rawVK, ok := vk.(interface {
		WriteRawTo(io.Writer) (int64, error)
	}); ok {
		rawVK.WriteRawTo(bwVK)
	} else {
		vk.WriteTo(bwVK)
	}
	bwVK.Flush()
	vkFile.Close()

	fmt.Println("   -> 初始化 VTLP 全局参数...")
	rsaSetup := protocol.RSAExpSetup()

	fmt.Println("   -> 生成发行方签名密钥...")
	signKey, _ := eddsa.New(tedwards.BN254, rand.Reader)
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
	yKey := protocol.GenPuzzle(seed, rsaSetup)

	// [系统工程特性 2]：使用 AES-GCM 信封加密凭证载荷
	aesCiphertext := AESGCMEncrypt(yKey, payloadBigInt.Bytes())
	fmt.Println("   -> [锁定完成] AES-GCM 密文已下发。\n")

	// -----------------------------------------------------------------------
	// 阶段 2: 消费 - 解谜
	// -----------------------------------------------------------------------
	fmt.Println("[Phase 2] 用户本地解谜 (Time-Lock Solving)...")
	solveStart := time.Now()

	userKey := ManualSolve(seed, rsaSetup.RSAMod, T)

	// 使用解出来的 userKey 进行 AES-GCM 解密
	recoveredPlaintext := AESGCMDecrypt(userKey, aesCiphertext)
	recoveredPayloadBigInt := new(big.Int).SetBytes(recoveredPlaintext)

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

	// [硬核加载]：没有任何回退！严格通过带有流式缓冲的 bufio 接口从硬盘读取二进制大文件！
	fmt.Println("   -> [System] 正在严格从物理磁盘文件 proving.key 读取并反序列化密钥...")
	pkFileIn, err := os.Open("proving.key")
	if err != nil {
		log.Fatal("物理磁盘读取 proving.key 失败!", err)
	}
	brPK := bufio.NewReader(pkFileIn) // 赋予 I/O 字节级流式读取能力
	loadedPK := groth16.NewProvingKey(ecc.BN254)
	if _, err := loadedPK.ReadFrom(brPK); err != nil {
		log.Fatal("从磁盘流反序列化 PK 彻底失败! ", err)
	}
	pkFileIn.Close()

	proveStart := time.Now()

	var assignment circuit.CredentialCircuit
	assignment.Root = calculatedRoot
	assignment.SN = snVal
	assignment.Issuer.Assign(ecc.BN254, pubKey.Bytes())

	assignment.Secret = secretVal
	assignment.Nullifier = nullifierVal
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

	// 强制使用磁盘反序列化的 loadedPK 进行证明
	proof, err := groth16.Prove(ccs, loadedPK, witness)
	if err != nil {
		log.Printf("   [错误] 证明生成失败: %v\n", err)
	} else {
		fmt.Printf("   -> [成功] 证明生成完毕! 耗时: %s\n", time.Since(proveStart))
	}

	// -----------------------------------------------------------------------
	// 阶段 4: 验证方核销
	// -----------------------------------------------------------------------
	fmt.Println("\n[Phase 4] 验证方核销 (Verification)...")

	fmt.Println("   -> [System] 服务端严格从物理磁盘加载 Verifying Key...")
	vkFileIn, err := os.Open("verifying.key")
	if err != nil {
		log.Fatal("物理磁盘读取 verifying.key 失败!", err)
	}
	brVK := bufio.NewReader(vkFileIn)
	loadedVK := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := loadedVK.ReadFrom(brVK); err != nil {
		log.Fatal("从磁盘流反序列化 VK 彻底失败! ", err)
	}
	vkFileIn.Close()

	verifyStart := time.Now()
	pubWitness, _ := witness.Public()

	// 强制使用磁盘反序列化的 loadedVK 进行验证
	err = groth16.Verify(proof, loadedVK, pubWitness)
	if err != nil {
		log.Fatal("ZKP 验证失败:", err)
	}

	fmt.Printf("   -> (A) 哈希重构 & (B) 双花推导: 通过\n")
	fmt.Printf("   -> (C) Merkle 状态包含性: 通过\n")
	fmt.Printf("   -> (D) EdDSA 签名合法性: 通过\n")
	fmt.Printf("   -> [成功] 全约束 ZKP 验证极速通过! 验证耗时: %s\n", time.Since(verifyStart))
	fmt.Println("\n------------------------------------------------")
	fmt.Println("🎉 真·全链路跑通！底层磁盘 I/O 与 AES-GCM 已彻底集成！")
}
