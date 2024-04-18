package models

import "encoding/json"

type JSONSignature struct {
	Type string `json:"type"`
	ED25519Signature
	MultiED25519Signature
	MultiAgentSignature
}

type ED25519Signature struct {
	PublicKey string `json:"public_key"`
	Signature string `json:"signature"`
}

type SignatureContent struct {
	Index     uint64
	Signature string
}

func (s *SignatureContent) UnmarshalJSON(raw []byte) error {
	if len(raw) >= 2 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		return json.Unmarshal(raw, &s.Signature)
	}
	var t struct {
		Index     uint64 `json:"index"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(raw, &t); err != nil {
		return err
	}
	s.Index, s.Signature = t.Index, t.Signature
	return nil
}

type MultiED25519Signature struct {
	PublicKeys []string           `json:"public_keys"`
	Signatures []SignatureContent `json:"signatures"`
	Threshold  uint8              `json:"threshold"`
	Bitmap     string             `json:"bitmap"`
}

type MultiAgentSignature struct {
	Sender                   JSONSigner   `json:"sender"`
	SecondarySignerAddresses []string     `json:"secondary_signer_addresses"`
	SecondarySigners         []JSONSigner `json:"secondary_signers"`
}

type JSONSigner struct {
	Type string `json:"type"`
	ED25519Signature
	MultiED25519Signature
}
