package utils

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// SecretTuple 是我们要锁进 VTLP 的秘密数据结构
// 包含：EdDSA签名(R, S) + Merkle路径(ProofSet, PathHelper)
type SecretTuple struct {
	// 签名部分 (EdDSA Signature R, S) -> 对应 []byte
	SigR []byte
	SigS []byte

	// Merkle 路径部分 (深度=3)
	// 注意：为了方便序列化，我们这里存 []byte，使用时再转回 fr.Element
	ProofSet   [][]byte
	PathHelper [][]byte
}

// Serialize 将 SecretTuple 转换为一个巨大的 big.Int (为了喂给 VTLP)
func Serialize(tuple SecretTuple) (*big.Int, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	// 使用 Go 原生 Gob 编码
	if err := enc.Encode(tuple); err != nil {
		return nil, fmt.Errorf("serialize error: %v", err)
	}

	// 将字节流转为大整数
	bigInt := new(big.Int).SetBytes(buf.Bytes())
	return bigInt, nil
}

// Deserialize 将 big.Int 还原回 SecretTuple
func Deserialize(b *big.Int) (*SecretTuple, error) {
	// 将大整数转回字节流
	byteData := b.Bytes()
	buf := bytes.NewBuffer(byteData)
	dec := gob.NewDecoder(buf)

	var tuple SecretTuple
	if err := dec.Decode(&tuple); err != nil {
		return nil, fmt.Errorf("deserialize error: %v", err)
	}

	return &tuple, nil
}

// ConvertFrToBytes 辅助函数：将 fr.Element 数组转为 [][]byte
func ConvertFrToBytes(elements []fr.Element) [][]byte {
	res := make([][]byte, len(elements))
	for i, e := range elements {
		// 修复点：先将返回值赋给变量 b，使其可寻址，然后再切片
		b := e.Bytes()
		res[i] = b[:]
	}
	return res
}

// ConvertBytesToFr 辅助函数：将 [][]byte 转回 fr.Element 数组
func ConvertBytesToFr(data [][]byte) []fr.Element {
	res := make([]fr.Element, len(data))
	for i, d := range data {
		res[i].SetBytes(d)
	}
	return res
}
