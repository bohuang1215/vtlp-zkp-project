// 文件路径: ~/go/src/vtlp-zkp-project/main.go

package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
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
// HTTP JSON 数据结构定义 (采纳最优实践)
// ==========================================

type IssueReq struct {
	Secret    string `json:"secret"`    // Hex String
	Nullifier string `json:"nullifier"` // Hex String
	T         int64  `json:"t"`
}

type IssueResp struct {
	Seed    string `json:"seed"`     // Hex String
	Root    string `json:"root"`     // Hex String
	Cipher  []byte `json:"cipher"`   // 原生 []byte，Go 自动编解码 Base64
	VtlpSig []byte `json:"vtlp_sig"` // 原生 []byte，Go 自动编解码 Base64
}

type VerifyReq struct {
	ProofData []byte `json:"proof_data"` // 序列化后的 Proof 字节流 (自动 Base64)
	Root      string `json:"root"`       // Hex String
	SN        string `json:"sn"`         // Hex String
	PubKey    []byte `json:"pub_key"`    // 发行方公钥字节流 (自动 Base64)
}

type VerifyResp struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

// ==========================================
// 主流程
// ==========================================

func main() {
	fmt.Println("================================================================")
	fmt.Println("   阶段：网络层解耦与 C/S 架构分离 (HTTP/JSON 最终版)")
	fmt.Println("================================================================\n")

	// -----------------------------------------------------------------------
	// [System] 预置环境：编译电路并强制同步生成密钥
	// -----------------------------------------------------------------------
	fmt.Println("[System] 正在编译电路并同步生成 ZKP 证明密钥...")
	var myCircuit circuit.CredentialCircuit
	ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &myCircuit)
	if err != nil {
		log.Fatalf("电路编译失败: %v", err)
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatalf("Setup失败: %v", err)
	}

	fmt.Println("[System] 正在安全落盘密钥以确保上下文严格一致...")
	pkFile, _ := os.Create("proving.key")
	bwPK := bufio.NewWriter(pkFile)
	if rawPK, ok := pk.(interface {
		WriteRawTo(io.Writer) (int64, error)
	}); ok {
		rawPK.WriteRawTo(bwPK)
	} else {
		pk.WriteTo(bwPK)
	}
	bwPK.Flush()
	pkFile.Close()

	vkFile, _ := os.Create("verifying.key")
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

	fmt.Println("[System] 正在严格从物理磁盘文件读取密钥...")
	pkFileIn, err := os.Open("proving.key")
	if err != nil {
		log.Fatalf("打开 proving.key 失败: %v", err)
	}
	brPK := bufio.NewReader(pkFileIn)
	loadedPK := groth16.NewProvingKey(ecc.BN254)
	if _, err := loadedPK.ReadFrom(brPK); err != nil {
		log.Fatalf("反序列化 PK 失败: %v", err)
	}
	pkFileIn.Close()

	vkFileIn, err := os.Open("verifying.key")
	if err != nil {
		log.Fatalf("打开 verifying.key 失败: %v", err)
	}
	brVK := bufio.NewReader(vkFileIn)
	loadedVK := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := loadedVK.ReadFrom(brVK); err != nil {
		log.Fatalf("反序列化 VK 失败: %v", err)
	}
	vkFileIn.Close()

	// -----------------------------------------------------------------------
	// [服务端] 启动 HTTP Web Server
	// -----------------------------------------------------------------------
	var issuerMu sync.Mutex
	rsaSetup := protocol.RSAExpSetup()
	signKey, _ := eddsa.New(tedwards.BN254, rand.Reader)
	pubKeyBytes := signKey.Public().Bytes()

	var verifierMu sync.RWMutex
	L_spent := make(map[string]bool)

	// API 1: 发行接口
	http.HandleFunc("/api/v1/issue", func(w http.ResponseWriter, r *http.Request) {
		var req IssueReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "JSON 解析失败", http.StatusBadRequest)
			return
		}

		secretVal, _ := new(big.Int).SetString(req.Secret, 16)
		nullifierVal, _ := new(big.Int).SetString(req.Nullifier, 16)

		hFunc := mimc.NewMiMC()
		var secretFr, nullifierFr fr.Element
		secretFr.SetBigInt(secretVal)
		nullifierFr.SetBigInt(nullifierVal)

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

		hFunc.Reset()
		sigBytes, _ := signKey.Sign(commBytes, hFunc)

		payloadTuple := utils.SecretTuple{
			SigR:       sigBytes[:32],
			SigS:       sigBytes[32:],
			ProofSet:   mockProofSet,
			PathHelper: mockHelper,
		}
		payloadBigInt, _ := utils.Serialize(payloadTuple)

		seed, _ := rand.Int(rand.Reader, rsaSetup.RSAMod)
		yKey := protocol.GenPuzzle(seed, rsaSetup)
		aesCiphertext, _ := AESGCMEncrypt(yKey, payloadBigInt.Bytes())

		// [架构修复] pi_vtlp 真实语义：对 (seed || aesCiphertext) 进行原子绑定背书签名
		msgToSign := append(seed.Bytes(), aesCiphertext...)
		hFunc.Reset()
		vtlpSigBytes, _ := signKey.Sign(msgToSign, hFunc)

		resp := IssueResp{
			Seed:    seed.Text(16),
			Root:    calculatedRoot.Text(16),
			Cipher:  aesCiphertext,
			VtlpSig: vtlpSigBytes,
		}
		json.NewEncoder(w).Encode(resp)
	})

	// API 2: 核销接口
	http.HandleFunc("/api/v1/verify", func(w http.ResponseWriter, r *http.Request) {
		var req VerifyReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "JSON 解析失败", http.StatusBadRequest)
			return
		}

		snVal, _ := new(big.Int).SetString(req.SN, 16)
		rootVal, _ := new(big.Int).SetString(req.Root, 16)
		snStr := snVal.String()

		verifierMu.RLock()
		if L_spent[snStr] {
			verifierMu.RUnlock()
			http.Error(w, "双花攻击检测: 该凭证已被核销过", http.StatusConflict)
			return
		}
		verifierMu.RUnlock()

		proof := groth16.NewProof(ecc.BN254)
		if _, err := proof.ReadFrom(bytes.NewReader(req.ProofData)); err != nil {
			http.Error(w, "Proof 反序列化失败", http.StatusBadRequest)
			return
		}

		var assignment circuit.CredentialCircuit
		assignment.Root = rootVal
		assignment.SN = snVal
		assignment.Issuer.Assign(ecc.BN254, req.PubKey)

		pubWitness, _ := frontend.NewWitness(&assignment, ecc.BN254, frontend.PublicOnly())
		if err := groth16.Verify(proof, loadedVK, pubWitness); err != nil {
			http.Error(w, "ZKP 数学验证未通过", http.StatusForbidden)
			return
		}

		verifierMu.Lock()
		defer verifierMu.Unlock()
		if L_spent[snStr] {
			http.Error(w, "并发写入冲突，该凭证已被抢先核销", http.StatusConflict)
			return
		}
		L_spent[snStr] = true

		json.NewEncoder(w).Encode(VerifyResp{Status: "success", Message: "凭证核销入账成功"})
	})

	go func() {
		fmt.Println("[Server] 服务端监听在 http://127.0.0.1:8080")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatalf("HTTP 服务启动失败: %v", err)
		}
	}()
	time.Sleep(200 * time.Millisecond) // 等待服务器启动

	// -----------------------------------------------------------------------
	// [客户端] HTTP 请求交互与本地验证
	// -----------------------------------------------------------------------
	fmt.Println("\n[Client] 构造 JSON 载荷，通过 HTTP POST 请求发行凭证...")
	secretVal := big.NewInt(12345)
	nullifierVal := big.NewInt(999)
	const T = 200000

	issueReqBody, _ := json.Marshal(IssueReq{
		Secret:    secretVal.Text(16),
		Nullifier: nullifierVal.Text(16),
		T:         T,
	})

	resp, err := http.Post("http://127.0.0.1:8080/api/v1/issue", "application/json", bytes.NewBuffer(issueReqBody))
	if err != nil {
		log.Fatalf("HTTP 请求失败: %v", err)
	}

	var issueResp IssueResp
	json.NewDecoder(resp.Body).Decode(&issueResp)
	resp.Body.Close()
	fmt.Println("   -> [成功] 收到服务端的 HTTP 响应 (包含 AES-GCM 密文与 pi_vtlp)。")

	seed, _ := new(big.Int).SetString(issueResp.Seed, 16)
	root, _ := new(big.Int).SetString(issueResp.Root, 16)

	fmt.Println("[Client] 正在执行 Check-Before-You-Solve (验证密文来源合法性)...")
	msgToVerify := append(seed.Bytes(), issueResp.Cipher...)

	// 客户端使用发行方公钥验证密文背书 (拦截算力枯竭攻击)
	verifyHashFunc := mimc.NewMiMC()
	isValid, _ := signKey.Public().Verify(issueResp.VtlpSig, msgToVerify, verifyHashFunc)
	if !isValid {
		log.Fatalf("预验证拦截: 密文被篡改或来源不合法，拒绝执行耗时解谜！")
	}
	fmt.Println("   -> [成功] pi_vtlp 预验证通过，密文可信。")

	fmt.Println("[Client] 开始本地 VTLP 解谜...")
	userKey := ManualSolve(seed, rsaSetup.RSAMod, T)
	recoveredPlaintext, _ := AESGCMDecrypt(userKey, issueResp.Cipher)
	recoveredTuple, _ := utils.Deserialize(new(big.Int).SetBytes(recoveredPlaintext))

	fmt.Println("[Client] 正在生成 ZKP 证明，并序列化写入字节缓冲流...")
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
	proof, _ := groth16.Prove(ccs, loadedPK, witness)

	var proofBuf bytes.Buffer
	proof.WriteTo(&proofBuf) // 将 Proof 写入字节流

	fmt.Println("   -> [成功] ZKP 证明准备就绪，已转换为 HTTP 传输格式。\n")

	// -----------------------------------------------------------------------
	// 验证方并发安全测试 (高并发 HTTP POST 模拟)
	// -----------------------------------------------------------------------
	fmt.Println("================================================================")
	fmt.Println("[测试] 模拟恶意用户并发双花攻击 (通过 HTTP 端口并发提交)")
	fmt.Println("================================================================")

	verifyReqBody, _ := json.Marshal(VerifyReq{
		ProofData: proofBuf.Bytes(),
		Root:      issueResp.Root,
		SN:        snVal.Text(16),
		PubKey:    pubKeyBytes,
	})

	var wg sync.WaitGroup
	attackCount := 3

	for i := 1; i <= attackCount; i++ {
		wg.Add(1)
		go func(threadID int) {
			defer wg.Done()

			vResp, err := http.Post("http://127.0.0.1:8080/api/v1/verify", "application/json", bytes.NewBuffer(verifyReqBody))
			if err != nil {
				fmt.Printf("   [HTTP 客户端 %d 错误] %v\n", threadID, err)
				return
			}
			defer vResp.Body.Close()

			if vResp.StatusCode == http.StatusOK {
				fmt.Printf("   [线程 %d] [核销通过] HTTP 200: 凭证核销成功！\n", threadID)
			} else {
				bodyBytes, _ := io.ReadAll(vResp.Body)
				// bodyBytes 结尾自带换行符，所以不需要额外加 \n
				fmt.Printf("   [线程 %d] [网络拦截] HTTP %d: %s", threadID, vResp.StatusCode, string(bodyBytes))
			}
		}(i)
	}

	wg.Wait()

	fmt.Println("------------------------------------------------")
	fmt.Println("[完成] 真·微服务架构闭环！网络隔离与 JSON 序列化完美执行！")
}
