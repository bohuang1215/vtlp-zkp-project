// 文件路径: ~/go/src/vtlp-zkp-project/main.go

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"sync"
	"time"

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
// 辅助函数：解谜与 AES-GCM
// ==========================================

func ManualSolve(seed, N *big.Int, T int64) *big.Int {
	result := new(big.Int).Set(seed)
	two := big.NewInt(2)
	for i := int64(0); i < T; i++ {
		result.Exp(result, two, N)
	}
	return result
}

func AESGCMEncrypt(y *big.Int, plaintext []byte) ([]byte, error) {
	hash := sha256.Sum256(y.Bytes())
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aesgcm.Seal(nonce, nonce, plaintext, nil), nil
}

func AESGCMDecrypt(y *big.Int, ciphertext []byte) ([]byte, error) {
	hash := sha256.Sum256(y.Bytes())
	block, err := aes.NewCipher(hash[:])
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesgcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("密文长度异常")
	}
	nonce, cipherData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return aesgcm.Open(nil, nonce, cipherData, nil)
}

// ==========================================
// 主流程：含并发双花攻击拦截测试
// ==========================================

func main() {
	fmt.Println("================================================================")
	fmt.Println("   阶段：引入高并发状态机与防双花账本 (Service & Mutex)")
	fmt.Println("================================================================\n")

	// -----------------------------------------------------------------------
	// [System] 预置环境：编译电路与生成密钥
	// 为了保证在演示并发时内存结构的绝对一致性，在此一次性完成环境 Setup
	// -----------------------------------------------------------------------
	fmt.Println("[System] 正在初始化基础设施 (编译电路与生成密钥)...")
	var myCircuit circuit.CredentialCircuit
	ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &myCircuit)
	if err != nil {
		log.Fatal(err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatal(err)
	}

	// -----------------------------------------------------------------------
	// [微服务架构模拟] 服务端：发行方 (Issuer Service)
	// -----------------------------------------------------------------------
	var issuerMu sync.Mutex
	rsaSetup := protocol.RSAExpSetup()
	signKey, _ := eddsa.New(tedwards.BN254, rand.Reader)
	pubKey := signKey.Public()
	pubKeyBytes := pubKey.Bytes() // 直接获取字节数组，避免接口传递

	// 并发安全的凭证发行接口
	issueCredential := func(secretVal, nullifierVal *big.Int, T int64) (*big.Int, *big.Int, []byte, error) {
		hFunc := mimc.NewMiMC()

		var secretFr, nullifierFr fr.Element
		secretFr.SetBigInt(secretVal)
		nullifierFr.SetBigInt(nullifierVal)

		secBytes := secretFr.Bytes()
		nulBytes := nullifierFr.Bytes()
		hFunc.Write(secBytes[:])
		hFunc.Write(nulBytes[:])
		commBytes := hFunc.Sum(nil)

		// --- 临界区：Merkle 树状态更新 (加互斥写锁) ---
		issuerMu.Lock()
		defer issuerMu.Unlock() // 放在 Lock 后立即 defer，保证任何情况下都会释放

		mockProofSet := make([][]byte, circuit.TreeDepth)
		mockHelper := make([][]byte, circuit.TreeDepth)
		currentHash := commBytes

		for i := 0; i < circuit.TreeDepth; i++ {
			var elemFr fr.Element
			elemFr.SetInt64(int64(100 + i))
			eBytes := elemFr.Bytes()
			mockProofSet[i] = eBytes[:]

			var zeroFr fr.Element
			zeroFr.SetInt64(0)
			zBytes := zeroFr.Bytes()
			mockHelper[i] = zBytes[:]

			hFunc.Reset()
			hFunc.Write(currentHash)
			hFunc.Write(mockProofSet[i])
			currentHash = hFunc.Sum(nil)
		}
		calculatedRoot := new(big.Int).SetBytes(currentHash)
		// --- 临界区结束 ---

		hFunc.Reset()
		sigBytes, err := signKey.Sign(commBytes, hFunc)
		if err != nil {
			return nil, nil, nil, err // defer 会在 return 时自动执行 Unlock
		}

		payloadTuple := utils.SecretTuple{
			SigR:       sigBytes[:32],
			SigS:       sigBytes[32:],
			ProofSet:   mockProofSet,
			PathHelper: mockHelper,
		}
		payloadBigInt, _ := utils.Serialize(payloadTuple)

		seed, _ := rand.Int(rand.Reader, rsaSetup.RSAMod)

		// 注：加密侧的 yKey 与解密侧的 userKey 在数学上严格等价 (均为 seed^(2^T) mod N)
		yKey := protocol.GenPuzzle(seed, rsaSetup)
		aesCiphertext, err := AESGCMEncrypt(yKey, payloadBigInt.Bytes())
		if err != nil {
			return nil, nil, nil, err
		}

		return seed, calculatedRoot, aesCiphertext, nil
	}

	// -----------------------------------------------------------------------
	// [微服务架构模拟] 服务端：验证方 (Verifier Service)
	// -----------------------------------------------------------------------
	var verifierMu sync.RWMutex
	L_spent := make(map[string]bool)

	// 并发安全的核销验证接口
	verifyCredential := func(proof groth16.Proof, root, sn *big.Int, pkBytes []byte) error {
		snStr := sn.String()

		// 1. 防双花检测 (加读锁，不阻塞并发校验)
		verifierMu.RLock()
		if L_spent[snStr] {
			verifierMu.RUnlock()
			return errors.New("该凭证已被核销过")
		}
		verifierMu.RUnlock()

		// 2. 构造公共输入并执行零知识验证 (脱离锁区间，充分利用多核 CPU 算力)
		var assignment circuit.CredentialCircuit
		assignment.Root = root
		assignment.SN = sn
		assignment.Issuer.Assign(ecc.BN254, pkBytes)

		pubWitness, err := frontend.NewWitness(&assignment, ecc.BN254, frontend.PublicOnly())
		if err != nil {
			return fmt.Errorf("公共输入构造失败: %v", err)
		}

		err = groth16.Verify(proof, vk, pubWitness)
		if err != nil {
			return fmt.Errorf("ZKP 数学验证未通过: %v", err)
		}

		// 3. 验证通过，状态变更入账 (加互斥写锁)
		verifierMu.Lock()
		defer verifierMu.Unlock()
		// Double-Check：防止读锁释放期间被其他线程抢占
		if L_spent[snStr] {
			return errors.New("并发写入冲突，该凭证已被抢先核销")
		}
		L_spent[snStr] = true

		return nil
	}

	fmt.Println("   [成功] 发行方服务与验证方服务已启动。\n")

	// ---------------------------------------------------------
	// 用户端行为模拟 (Client Simulation)
	// ---------------------------------------------------------
	secretVal := big.NewInt(12345)
	nullifierVal := big.NewInt(999)
	const T = 200000

	fmt.Println("[Client] 正在向 Issuer 请求发行凭证...")
	seed, root, aesCiphertext, err := issueCredential(secretVal, nullifierVal, T)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("   -> [成功] 获取到 AES-GCM 锁定密文。")

	fmt.Println("[Client] 开始本地 VTLP 解谜...")
	// 注：解密侧的 userKey 与加密侧的 yKey 在数学上严格等价
	userKey := ManualSolve(seed, rsaSetup.RSAMod, T)
	recoveredPlaintext, err := AESGCMDecrypt(userKey, aesCiphertext)
	if err != nil {
		log.Fatal(err)
	}

	recoveredTuple, _ := utils.Deserialize(new(big.Int).SetBytes(recoveredPlaintext))

	fmt.Println("[Client] 正在生成 ZKP 证明...")

	hFunc := mimc.NewMiMC()
	var nullifierFr fr.Element
	nullifierFr.SetBigInt(nullifierVal)
	nBytes := nullifierFr.Bytes()
	hFunc.Write(nBytes[:])
	snVal := new(big.Int).SetBytes(hFunc.Sum(nil))

	var assignment circuit.CredentialCircuit
	assignment.Root = root
	assignment.SN = snVal
	assignment.Issuer.Assign(ecc.BN254, pubKeyBytes)
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

	proofStart := time.Now()
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Fatal("生成证明失败:", err)
	}
	fmt.Printf("   -> [成功] ZKP 证明准备就绪！耗时: %v\n\n", time.Since(proofStart))

	// ---------------------------------------------------------
	// 验证方并发安全测试 (高并发双花攻击模拟)
	// ---------------------------------------------------------
	fmt.Println("================================================================")
	fmt.Println("[测试] 模拟恶意用户发动并发双花攻击 (启动 3 个并发线程提交相同证明)")
	fmt.Println("================================================================")

	var wg sync.WaitGroup
	attackCount := 3

	for i := 1; i <= attackCount; i++ {
		wg.Add(1)
		go func(threadID int) {
			defer wg.Done()

			// 并发调用 Verifier 服务的核销接口
			err := verifyCredential(proof, root, snVal, pubKeyBytes)
			if err != nil {
				fmt.Printf("   [线程 %d] [拦截] 双花攻击检测: %v\n", threadID, err)
			} else {
				fmt.Printf("   [线程 %d] [成功] 凭证核销成功，已安全入账 L_spent！\n", threadID)
			}
		}(i)
	}

	wg.Wait()

	fmt.Println("\n------------------------------------------------")
	fmt.Println("[完成] 并发双花防御机制验证结束！读写锁与状态机运转完美！")
}
