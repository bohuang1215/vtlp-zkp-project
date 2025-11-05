// (文件路径: ~/go/src/vtlp-zkp-project/circuit/circuit.go)

package circuit

import (
	"errors" // (导入 errors)

	"github.com/consensys/gnark/frontend"
	std_mimc "github.com/consensys/gnark/std/hash/mimc"
)

// 树的深度 (8 个叶子 = 深度 3)
const TreeDepth = 3

// ------------------------------------------------------------------
// 最终电路（A+B+D 融合版）
// ------------------------------------------------------------------
type SpendCircuit_Final struct { // (改名为 Final)
	// --- 公共输入 x ---
	Root      frontend.Variable `gnark:",public"`
	Nullifier frontend.Variable `gnark:",public"`

	// (新增!) 断言 D (时效)
	T_Expiry  frontend.Variable `gnark:",public"`
	T_Current frontend.Variable `gnark:",public"`

	// --- 私有见证 w ---
	Secret frontend.Variable `gnark:",secret"`

	// (断言 B) Merkle 路径
	ProofSet   [TreeDepth]frontend.Variable `gnark:",secret"`
	PathHelper [TreeDepth]frontend.Variable `gnark:",secret"`
}

// ------------------------------------------------------------------
// Define 函数 (A+B+D)
// ------------------------------------------------------------------
func (circuit *SpendCircuit_Final) Define(api frontend.API) error {

	// 1. 实例化 MiMC 哈希器
	mimc, err := std_mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// --- 断言 1: 承诺计算 (A) ---
	mimc.Write(circuit.Secret, circuit.Nullifier)
	comm := mimc.Sum()

	// --- 断言 2: Merkle 证明 (B) ---
	currentHash := comm

	// (检查长度，v2.3 中没有，v3.5 中有，我们加上更健壮)
	if len(circuit.ProofSet) != len(circuit.PathHelper) {
		return errors.New("ProofSet and PathHelper lengths do not match")
	}

	for i := 0; i < TreeDepth; i++ {
		mimc.Reset()
		pathElement := circuit.ProofSet[i]
		helperElement := circuit.PathHelper[i]
		left := api.Select(helperElement, pathElement, currentHash)
		right := api.Select(helperElement, currentHash, pathElement)
		mimc.Write(left, right)
		currentHash = mimc.Sum()
	}
	api.AssertIsEqual(currentHash, circuit.Root)

	// --- (新增!) 断言 4: 时效性断言 (D) ---
	// api.AssertIsLessOrEqual(A, B) 检查 A <= B
	api.AssertIsLessOrEqual(circuit.T_Current, circuit.T_Expiry)

	return nil
}
