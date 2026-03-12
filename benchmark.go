// // 文件路径: ~/go/src/vtlp-zkp-project/benchmark.go

// package main

// import (
// 	"crypto/rand"
// 	"fmt"
// 	"math/big"
// 	"time"

// 	"github.com/consensys/gnark-crypto/ecc"
// 	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
// 	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
// 	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
// 	"github.com/consensys/gnark-crypto/signature/eddsa"

// 	"github.com/consensys/gnark/backend/groth16"
// 	"github.com/consensys/gnark/frontend"
// 	"github.com/consensys/gnark/frontend/cs/r1cs"

// 	"github.com/VTLP/protocol"
// 	"vtlp.dev/m/circuit"
// 	"vtlp.dev/m/utils"
// )

// func ManualSolveBench(seed, N *big.Int, T int64) time.Duration {
// 	result := new(big.Int).Set(seed)
// 	two := big.NewInt(2)
// 	start := time.Now()
// 	for i := int64(0); i < T; i++ {
// 		result.Exp(result, two, N)
// 	}
// 	return time.Since(start)
// }

// func main() {
// 	fmt.Println("================================================================")
// 	fmt.Println("   第5章: 自动化实验基准测试 (Benchmark Suite)")
// 	fmt.Println("================================================================\n")

// 	// -------------------------------------------------------------------
// 	// 实验一: VTLP 时效性时间参数 T 的线性度分析
// 	// -------------------------------------------------------------------
// 	fmt.Println(">>> [实验一] VTLP 时间锁解谜耗时测试")
// 	fmt.Printf("%-15s | %-20s\n", "时间参数 (T)", "解谜耗时 (Solve Time)")
// 	fmt.Println("----------------------------------------")

// 	rsaSetup := protocol.RSAExpSetup()
// 	seed, _ := rand.Int(rand.Reader, rsaSetup.RSAMod)

// 	T_values := []int64{100000, 200000, 500000, 1000000, 2000000}
// 	for _, t := range T_values {
// 		duration := ManualSolveBench(seed, rsaSetup.RSAMod, t)
// 		fmt.Printf("%-15d | %-20v\n", t, duration)
// 	}
// 	fmt.Println()

// 	// -------------------------------------------------------------------
// 	// 实验二: ZKP 随树深度演进的性能开销测试
// 	// -------------------------------------------------------------------
// 	fmt.Println(">>> [实验二] ZKP 电路约束与耗时演进测试")
// 	fmt.Printf("%-8s | %-12s | %-15s | %-15s\n", "树深度", "约束数(条)", "Prove耗时", "Verify耗时")
// 	fmt.Println("---------------------------------------------------------------")

// 	signKey, _ := eddsa.New(tedwards.BN254, rand.Reader)
// 	pubKey := signKey.Public()
// 	secretVal, nullifierVal := big.NewInt(12345), big.NewInt(999)

// 	hFunc := mimc.NewMiMC()
// 	var secretFr, nullifierFr fr.Element
// 	secretFr.SetBigInt(secretVal)
// 	nullifierFr.SetBigInt(nullifierVal)

// 	// [修复] 将 [32]byte 数组转换为 []byte 切片，并分两次 Write
// 	secBytes := secretFr.Bytes()
// 	nulBytes := nullifierFr.Bytes()
// 	hFunc.Write(secBytes[:])
// 	hFunc.Write(nulBytes[:])
// 	commBytes := hFunc.Sum(nil)

// 	hFunc.Reset()
// 	hFunc.Write(nulBytes[:])
// 	snBytes := hFunc.Sum(nil)
// 	snVal := new(big.Int).SetBytes(snBytes)

// 	depths := []int{3, 5, 10, 15, 20}
// 	for _, d := range depths {
// 		// 动态分配切片长度以适应当前深度
// 		myCircuit := circuit.CredentialCircuit{
// 			PathElements: make([]frontend.Variable, d),
// 			PathIndices:  make([]frontend.Variable, d),
// 		}

// 		ccs, _ := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &myCircuit)
// 		constraints := ccs.GetNbConstraints()

// 		pk, vk, _ := groth16.Setup(ccs)

// 		// 模拟生成指定深度的默克尔树路径
// 		currentHash := commBytes
// 		mockProofSet := make([][]byte, d)
// 		mockHelper := make([][]byte, d)
// 		for i := 0; i < d; i++ {
// 			var elemFr, zeroFr fr.Element
// 			elemFr.SetInt64(int64(100 + i))
// 			zeroFr.SetInt64(0)

// 			// [修复] 解决 cannot use [32]byte as []byte 的问题
// 			eBytes := elemFr.Bytes()
// 			mockProofSet[i] = eBytes[:]
// 			zBytes := zeroFr.Bytes()
// 			mockHelper[i] = zBytes[:]

// 			hFunc.Reset()
// 			hFunc.Write(currentHash)
// 			hFunc.Write(mockProofSet[i])
// 			currentHash = hFunc.Sum(nil)
// 		}
// 		calculatedRoot := new(big.Int).SetBytes(currentHash)

// 		hFunc.Reset()
// 		sigBytes, _ := signKey.Sign(commBytes, hFunc)

// 		// 填充 Witness
// 		var assignment circuit.CredentialCircuit
// 		assignment.Root = calculatedRoot
// 		assignment.SN = snVal
// 		assignment.Issuer.Assign(ecc.BN254, pubKey.Bytes())
// 		assignment.Secret = secretVal
// 		assignment.Nullifier = nullifierVal
// 		assignment.Sig.Assign(ecc.BN254, sigBytes)

// 		assignment.PathElements = make([]frontend.Variable, d)
// 		assignment.PathIndices = make([]frontend.Variable, d)
// 		recProofSet := utils.ConvertBytesToFr(mockProofSet)
// 		recHelper := utils.ConvertBytesToFr(mockHelper)
// 		for i := 0; i < d; i++ {
// 			assignment.PathElements[i] = recProofSet[i]
// 			assignment.PathIndices[i] = recHelper[i]
// 		}

// 		witness, _ := frontend.NewWitness(&assignment, ecc.BN254)

// 		// 计时 Prove
// 		startProve := time.Now()
// 		proof, _ := groth16.Prove(ccs, pk, witness)
// 		proveTime := time.Since(startProve)

// 		// 计时 Verify
// 		pubWitness, _ := witness.Public()
// 		startVerify := time.Now()
// 		_ = groth16.Verify(proof, vk, pubWitness)
// 		verifyTime := time.Since(startVerify)

// 		fmt.Printf("%-10d | %-16d | %-17v | %-15v\n", d, constraints, proveTime, verifyTime)
// 	}
// 	fmt.Println("\n[测试完成] 请将上述控制台输出数据复制到 Excel 中进行绘图。")
// }
