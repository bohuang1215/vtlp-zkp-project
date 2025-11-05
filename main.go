// (文件路径: ~/go/src/vtlp-zkp-project/main.go)

package main

import (
	"crypto/rand"
	"fmt"
	"log"

	// 导入 big.Int
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/signature"

	"github.com/cbergoon/merkletree"
	crypto_mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"

	// 导入 "电路外" 的 EdDSA (来自 v0.10.0)
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	crypto_eddsa "github.com/consensys/gnark-crypto/signature/eddsa"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"vtlp.dev/m/circuit" // 导入你的电路
)

// (ZKPContent 辅助内容不变)
type ZKPContent struct{ data []byte }

func (z ZKPContent) CalculateHash() ([]byte, error) {
	h := crypto_mimc.NewMiMC()
	h.Write(z.data)
	return h.Sum(nil), nil
}
func (z ZKPContent) Equals(other merkletree.Content) (bool, error) {
	return string(z.data) == string(other.(ZKPContent).data), nil
}

// --------------------------------

// --- "电路外" MiMC H(L,R) 辅助函数 ---
// (V4.0 修复： 必须使用 "顺序" 哈希，而不是 "拼接" 哈希)
func mimcHash(left, right *fr.Element) fr.Element {
	h_out := crypto_mimc.NewMiMC()

	// -----------------------------------------------------------
	// 关键修复 1: (H(L, R) 顺序哈希)
	// 这 100% 匹配了 circuit.go 中的 mimc.Write(left, right) 逻辑
	h_out.Write(left.Marshal())
	h_out.Write(right.Marshal())
	// -----------------------------------------------------------

	var result fr.Element
	result.SetBytes(h_out.Sum(nil))
	return result
}

// --------------------------------

// --- 运行主函数 ---
func main() {
	fmt.Println("--- 实验阶段 2.4：最终可行方案 (A+B+D 电路内, C 电路外) ---")

	// -------------------------------------
	// 1. "电路外" 的数据准备
	// -------------------------------------

	// 1.1 (A) 承诺数据
	secretValue := int64(123)
	nullifierValue := int64(456)
	var secretElement, nullifierElement fr.Element
	secretElement.SetInt64(secretValue)
	nullifierElement.SetInt64(nullifierValue)

	// -----------------------------------------------------------
	// 关键修复 2: (H(S, N) 顺序哈希)
	// (commElement 必须也使用顺序哈希)
	h_comm := crypto_mimc.NewMiMC()
	h_comm.Write(secretElement.Marshal())
	h_comm.Write(nullifierElement.Marshal())
	var commElement fr.Element
	commElement.SetBytes(h_comm.Sum(nil))
	commBytes := commElement.Marshal()
	// -----------------------------------------------------------

	// 1.2 (B) Merkle 树数据
	var leaves []merkletree.Content
	leaves = append(leaves, ZKPContent{data: commBytes}) // 叶子0
	for i := 1; i <= 7; i++ {
		var e fr.Element
		e.SetInt64(int64(i * 100))
		leaves = append(leaves, ZKPContent{data: e.Marshal()})
	}

	// cbergoon 库内部会调用 ZKPContent.CalculateHash()
	// ZKPContent.CalculateHash() 使用 h.Write(z.data)
	// 这是一个 H(data) 的哈希，*不是* H(L,R)
	// (这又是一个Bug)
	//
	// 我们必须 *完全* 抛弃 cbergoon，回到 V3.9 的手动树！
	// (我 V3.9 的手动树逻辑是正确的，但哈希是 H(L+R) 错了)
	//
	// 我们现在结合 V3.9 的 "手动树" 和 V2.3 的 "H(L,R)" 哈希

	// (V4.0) 手动构建 Merkle 树
	var leavesElements [8]fr.Element
	leavesElements[0] = commElement // 叶子0: 我们的 comm
	for i := 1; i <= 7; i++ {
		leavesElements[i].SetInt64(int64(i * 100))
	}
	// (Level 1)
	h01 := mimcHash(&leavesElements[0], &leavesElements[1])
	h23 := mimcHash(&leavesElements[2], &leavesElements[3])
	h45 := mimcHash(&leavesElements[4], &leavesElements[5])
	h67 := mimcHash(&leavesElements[6], &leavesElements[7])
	// (Level 2)
	h0123 := mimcHash(&h01, &h23)
	h4567 := mimcHash(&h45, &h67)
	// (Root)
	rootElement := mimcHash(&h0123, &h4567)
	rootBytes := rootElement.Marshal()

	// 1.3 (B) 路径和辅助
	var pathForAssignment [circuit.TreeDepth]frontend.Variable
	pathForAssignment[0] = leavesElements[1].Marshal() // l1
	pathForAssignment[1] = h23.Marshal()               // h23
	pathForAssignment[2] = h4567.Marshal()             // h4567
	var helperForAssignment [circuit.TreeDepth]frontend.Variable
	helperForAssignment[0] = 0
	helperForAssignment[1] = 0
	helperForAssignment[2] = 0

	// 1.4 (C) EdDSA 签名数据 (电路外)
	hFunc := crypto_mimc.NewMiMC()
	signer, err := crypto_eddsa.New(twistededwards.BN254, rand.Reader)
	if err != nil {
		log.Fatal("EdDSA 密钥生成失败:", err)
	}
	privKey, ok := signer.(signature.Signer) // (v0.10.0 API: 它是 signature.Signer)
	if !ok {
		log.Fatal("eddsa.New 返回了未知的 Signer 类型")
	}
	pubKey := privKey.Public()
	sig, err := privKey.Sign(commBytes, hFunc)
	if err != nil {
		log.Fatal("EdDSA 签名失败:", err)
	}

	// 1.5 (D) 时间戳数据 (不变)
	t_current := int64(100)
	t_expiry := int64(150)

	fmt.Println("电路外数据准备就绪 (A+B+C+D)")
	fmt.Println("  - Public Root:", rootBytes)
	fmt.Println("  - Public Nullifier:", nullifierValue)

	// 2. 编译 "A+B+D" 融合电路
	var circuitABD circuit.SpendCircuit_Final
	ccs, err := frontend.Compile(ecc.BN254, r1cs.NewBuilder, &circuitABD)
	if err != nil {
		fmt.Println("电路(A+B+D)编译失败:", err)
		return
	}
	fmt.Println("最终电路(A+B+D)编译成功! 约束数量:", ccs.GetNbConstraints())

	// 3. 准备 ZKP 证明 (A+B+D)
	goodAssignment := &circuit.SpendCircuit_Final{
		Root:       rootBytes,
		Nullifier:  nullifierValue,
		T_Expiry:   t_expiry,
		T_Current:  t_current,
		Secret:     secretValue,
		ProofSet:   pathForAssignment,
		PathHelper: helperForAssignment,
	}

	goodWitness, _ := frontend.NewWitness(goodAssignment, ecc.BN254)

	fmt.Println("\n--- Verifier 开始验证 ---")

	// 4. Verifier 验证 "Good Witness"

	// 4.1 Verifier 检查 "断言 C" (签名) - 电路外
	isValid, err := pubKey.Verify(sig, commBytes, hFunc)
	if err != nil || !isValid {
		log.Fatal("测试失败! (C) 电路外签名验证失败。")
	}
	fmt.Println("  (C) 签名验证通过。")

	// 4.2 Verifier 检查 "断言 A+B+D" (ZKP) - 电路内
	err = ccs.IsSolved(goodWitness)
	if err != nil {
		log.Fatal("测试失败! (A+B+D) ZKP 验证失败:", err)
	}
	fmt.Println("  (A+B+D) ZKP 验证通过。")
	fmt.Println("测试成功 (Good Witness)! 最终方案(A+B+D in, C out)通过。")

	// 5. Verifier 验证 "Bad Witness"
	fmt.Println("\n--- Verifier 验证 (Bad Witness - Time Expired) ---")
	badAssignment_Time := &circuit.SpendCircuit_Final{
		Root:       rootBytes,
		Nullifier:  nullifierValue,
		T_Expiry:   t_expiry,
		T_Current:  int64(160), // (已过期)
		Secret:     secretValue,
		ProofSet:   pathForAssignment,
		PathHelper: helperForAssignment,
	}

	badWitness_Time, _ := frontend.NewWitness(badAssignment_Time, ecc.BN254)
	err = ccs.IsSolved(badWitness_Time)
	if err == nil {
		fmt.Println("!!! ZKP逻辑错误: 错误的(过期)Witness居然通过了验证 !!!")
	} else {
		fmt.Println("测试成功 (badWitness D)! ZKP 成功拒绝了 (时间已过期)。")
	}

	fmt.Println("\n--- 恭喜! 你已掌握了最终可行方案的核心逻辑 ---")
}
