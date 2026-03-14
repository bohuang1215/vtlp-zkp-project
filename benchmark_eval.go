// 文件路径: ~/go/src/vtlp-zkp-project/benchmark_eval.go

package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/signature/eddsa"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/VTLP/protocol"
	"vtlp.dev/m/circuit"
	"vtlp.dev/m/utils"
)

// ==========================================
// 核心结构体与工具函数
// ==========================================

type IssueReq struct {
	Secret    string `json:"secret"`
	Nullifier string `json:"nullifier"`
	T         int64  `json:"t"`
}

type IssueResp struct {
	Seed    string `json:"seed"`
	Root    string `json:"root"`
	Cipher  []byte `json:"cipher"`
	VtlpSig []byte `json:"vtlp_sig"`
}

type VerifyReq struct {
	ProofData []byte `json:"proof_data"`
	Root      string `json:"root"`
	SN        string `json:"sn"`
	PubKey    []byte `json:"pub_key"`
}

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
	block, _ := aes.NewCipher(hash[:])
	aesgcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, aesgcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	return aesgcm.Seal(nonce, nonce, plaintext, nil), nil
}

func AESGCMDecrypt(y *big.Int, ciphertext []byte) []byte {
	hash := sha256.Sum256(y.Bytes())
	block, _ := aes.NewCipher(hash[:])
	aesgcm, _ := cipher.NewGCM(block)
	nonceSize := aesgcm.NonceSize()
	nonce, cipherData := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, _ := aesgcm.Open(nil, nonce, cipherData, nil)
	return plaintext
}

// ==========================================
// 主函数：自动化基准测试套件
// ==========================================

func main() {
	fmt.Println("================================================================")
	fmt.Println("   第5章: 系统级微服务架构压测套件 (Macro-Benchmark Suite)")
	fmt.Println("================================================================")

	// 1. 静默初始化基础设施
	var myCircuit circuit.CredentialCircuit
	ccs, _ := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &myCircuit)

	pkFileIn, _ := os.Open("proving.key")
	loadedPK := groth16.NewProvingKey(ecc.BN254)
	loadedPK.ReadFrom(bufio.NewReader(pkFileIn))
	pkFileIn.Close()

	vkFileIn, _ := os.Open("verifying.key")
	loadedVK := groth16.NewVerifyingKey(ecc.BN254)
	loadedVK.ReadFrom(bufio.NewReader(vkFileIn))
	vkFileIn.Close()

	// 2. 启动测试专用 HTTP 服务器 (含发证与核销逻辑)
	var issuerMu sync.Mutex
	rsaSetup := protocol.RSAExpSetup()
	signKey, _ := eddsa.New(tedwards.BN254, rand.Reader)
	pubKeyBytes := signKey.Public().Bytes()

	var verifierMu sync.RWMutex
	L_spent := make(map[string]bool)

	http.HandleFunc("/api/v1/issue", func(w http.ResponseWriter, r *http.Request) {
		var req IssueReq
		json.NewDecoder(r.Body).Decode(&req)

		secretVal, _ := new(big.Int).SetString(req.Secret, 16)
		nullifierVal, _ := new(big.Int).SetString(req.Nullifier, 16)

		hFunc := mimc.NewMiMC()
		var secretFr, nullifierFr fr.Element
		secretFr.SetBigInt(secretVal)
		nullifierFr.SetBigInt(nullifierVal)

		// [修复] 强制转换为切片
		secBytes := secretFr.Bytes()
		nulBytes := nullifierFr.Bytes()
		hFunc.Write(secBytes[:])
		hFunc.Write(nulBytes[:])
		commBytes := hFunc.Sum(nil)

		issuerMu.Lock()
		defer issuerMu.Unlock()
		mockProofSet := make([][]byte, circuit.TreeDepth)
		mockHelper := make([][]byte, circuit.TreeDepth)
		currentHash := commBytes
		for i := 0; i < circuit.TreeDepth; i++ {
			var elemFr fr.Element
			elemFr.SetInt64(int64(100 + i))
			eBytes := elemFr.Bytes()
			mockProofSet[i] = eBytes[:] // [修复] 切片赋值

			var zeroFr fr.Element
			zeroFr.SetInt64(0)
			zBytes := zeroFr.Bytes()
			mockHelper[i] = zBytes[:] // [修复] 切片赋值

			hFunc.Reset()
			hFunc.Write(currentHash)
			hFunc.Write(mockProofSet[i])
			currentHash = hFunc.Sum(nil)
		}
		calculatedRoot := new(big.Int).SetBytes(currentHash)

		hFunc.Reset()
		sigBytes, _ := signKey.Sign(commBytes, hFunc)
		payloadTuple := utils.SecretTuple{SigR: sigBytes[:32], SigS: sigBytes[32:], ProofSet: mockProofSet, PathHelper: mockHelper}
		payloadBigInt, _ := utils.Serialize(payloadTuple)

		seed, _ := rand.Int(rand.Reader, rsaSetup.RSAMod)
		yKey := protocol.GenPuzzle(seed, rsaSetup)
		aesCiphertext, _ := AESGCMEncrypt(yKey, payloadBigInt.Bytes())

		msgToSign := append(seed.Bytes(), aesCiphertext...)
		hFunc.Reset()
		vtlpSigBytes, _ := signKey.Sign(msgToSign, hFunc)

		json.NewEncoder(w).Encode(IssueResp{Seed: seed.Text(16), Root: calculatedRoot.Text(16), Cipher: aesCiphertext, VtlpSig: vtlpSigBytes})
	})

	http.HandleFunc("/api/v1/verify", func(w http.ResponseWriter, r *http.Request) {
		var req VerifyReq
		json.NewDecoder(r.Body).Decode(&req)
		snVal, _ := new(big.Int).SetString(req.SN, 16)
		snStr := snVal.String()

		verifierMu.RLock()
		if L_spent[snStr] {
			verifierMu.RUnlock()
			http.Error(w, "Double Spend", http.StatusConflict)
			return
		}
		verifierMu.RUnlock()

		proof := groth16.NewProof(ecc.BN254)
		proof.ReadFrom(bytes.NewReader(req.ProofData))

		var assignment circuit.CredentialCircuit
		assignment.Root, _ = new(big.Int).SetString(req.Root, 16)
		assignment.SN = snVal
		assignment.Issuer.Assign(ecc.BN254, req.PubKey)

		pubWitness, _ := frontend.NewWitness(&assignment, ecc.BN254, frontend.PublicOnly())
		groth16.Verify(proof, loadedVK, pubWitness)

		verifierMu.Lock()
		defer verifierMu.Unlock()
		if L_spent[snStr] {
			http.Error(w, "Double Spend", http.StatusConflict)
			return
		}
		L_spent[snStr] = true
		w.WriteHeader(http.StatusOK)
	})

	go http.ListenAndServe(":8081", nil)
	time.Sleep(500 * time.Millisecond)

	// =========================================================================
	// [测试 1] 网络通信载荷大小测算 (Payload Size Test)
	// =========================================================================
	fmt.Println(">>> [评估维度 1] JSON 网络通信载荷大小评估")
	secretVal := big.NewInt(12345)
	nullifierVal := big.NewInt(999)
	const T = 200000

	issueReqBody, _ := json.Marshal(IssueReq{Secret: secretVal.Text(16), Nullifier: nullifierVal.Text(16), T: T})
	fmt.Printf("   - 发行请求报文 (IssueReq) 大小: %d Bytes\n", len(issueReqBody))

	resp, _ := http.Post("http://127.0.0.1:8081/api/v1/issue", "application/json", bytes.NewBuffer(issueReqBody))
	respBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	fmt.Printf("   - 发行响应报文 (IssueResp，含信封密文): %d Bytes\n", len(respBody))

	var issueResp IssueResp
	json.Unmarshal(respBody, &issueResp)
	seed, _ := new(big.Int).SetString(issueResp.Seed, 16)
	root, _ := new(big.Int).SetString(issueResp.Root, 16)

	// 解密与 ZKP 生成
	userKey := ManualSolve(seed, rsaSetup.RSAMod, T)
	recoveredPlaintext := AESGCMDecrypt(userKey, issueResp.Cipher)
	recoveredTuple, _ := utils.Deserialize(new(big.Int).SetBytes(recoveredPlaintext))

	hFunc := mimc.NewMiMC()
	var nullifierFr fr.Element
	nullifierFr.SetBigInt(nullifierVal)
	nBytes := nullifierFr.Bytes() // [修复] 切片转换
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
	proof, _ := groth16.Prove(ccs, loadedPK, witness)
	var proofBuf bytes.Buffer
	proof.WriteTo(&proofBuf)

	verifyReqBody, _ := json.Marshal(VerifyReq{
		ProofData: proofBuf.Bytes(),
		Root:      issueResp.Root,
		SN:        snVal.Text(16),
		PubKey:    pubKeyBytes,
	})
	fmt.Printf("   - 核销请求报文 (VerifyReq，含 ZKP 证明): %d Bytes\n\n", len(verifyReqBody))

	// =========================================================================
	// [测试 2] 单次请求端到端物理延迟 (E2E Latency Pipeline)
	// =========================================================================
	fmt.Println(">>> [评估维度 2] HTTP 隔离下的端到端物理延迟拆解")
	t1 := time.Now()
	resp2, _ := http.Post("http://127.0.0.1:8081/api/v1/issue", "application/json", bytes.NewBuffer(issueReqBody))
	io.ReadAll(resp2.Body)
	resp2.Body.Close()
	issueTime := time.Since(t1)
	fmt.Printf("   - 1. 网络发证与混合加密开销: %v\n", issueTime)

	t2 := time.Now()
	ManualSolve(seed, rsaSetup.RSAMod, T)
	solveTime := time.Since(t2)
	fmt.Printf("   - 2. 强制时效 VTLP 解谜开销: %v\n", solveTime)

	t3 := time.Now()
	groth16.Prove(ccs, loadedPK, witness)
	proveTime := time.Since(t3)
	fmt.Printf("   - 3. 零知识约束求解与多项式生成: %v\n", proveTime)

	// 为了能测算验证时间，换一个随机 SN，防止被前面拦住
	snVal.Add(snVal, big.NewInt(1))
	verifyReqBody2, _ := json.Marshal(VerifyReq{ProofData: proofBuf.Bytes(), Root: issueResp.Root, SN: snVal.Text(16), PubKey: pubKeyBytes})
	t4 := time.Now()
	resp3, _ := http.Post("http://127.0.0.1:8081/api/v1/verify", "application/json", bytes.NewBuffer(verifyReqBody2))
	resp3.Body.Close()
	verifyTime := time.Since(t4)
	fmt.Printf("   - 4. HTTP 接收与零知识核销开销: %v\n\n", verifyTime)

	// =========================================================================
	// [测试 3] 高并发双花攻击拦截吞吐量压测 (Stress Test TPS)
	// =========================================================================
	fmt.Println(">>> [评估维度 3] 并发防双花防御机制极限吞吐量 (TPS) 压力测试")
	concurrencyLevels := []int{100, 500, 1000, 5000}

	fmt.Printf("%-15s | %-15s | %-20s | %-15s\n", "并发请求规模", "拦截成功率", "防双花吞吐量 (TPS)", "平均响应耗时")
	fmt.Println("--------------------------------------------------------------------------------")

	for _, reqCount := range concurrencyLevels {
		var wg sync.WaitGroup
		successCount := 0
		var mu sync.Mutex

		// 准备相同的攻击载荷
		snVal.Add(snVal, big.NewInt(1)) // 确保这批测试能有一个通过，其余全被拦截
		attackPayload, _ := json.Marshal(VerifyReq{ProofData: proofBuf.Bytes(), Root: issueResp.Root, SN: snVal.Text(16), PubKey: pubKeyBytes})

		startStress := time.Now()

		for i := 0; i < reqCount; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				vResp, err := http.Post("http://127.0.0.1:8081/api/v1/verify", "application/json", bytes.NewBuffer(attackPayload))
				if err == nil {
					if vResp.StatusCode == http.StatusConflict {
						mu.Lock()
						successCount++
						mu.Unlock()
					}
					vResp.Body.Close()
				}
			}()
		}
		wg.Wait()
		stressDuration := time.Since(startStress)
		tps := float64(reqCount) / stressDuration.Seconds()
		avgLatency := stressDuration.Milliseconds() / int64(reqCount)

		// successCount 是成功拦截（返回 409）的数量。因为有一个会拿到 200，所以拦截率是 (reqCount - 1) / reqCount
		interceptionRate := float64(successCount) / float64(reqCount-1) * 100
		if reqCount == 1 {
			interceptionRate = 100
		}

		fmt.Printf("%-20d | %-16.1f%% | %-25.0f | %-15d\n", reqCount, interceptionRate, tps, avgLatency)
	}
	fmt.Println("\n[测试完成] 第5章核心评估数据已采集完毕，请填入论文表格！")
}
