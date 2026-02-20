package reflex

const ReflexMagic = 0x5246584C // "REFX" در ASCII

type ClientHandshake struct {
	PublicKey [32]byte // کلید عمومی X25519
	UserID    [16]byte // UUID (16 بایت)
	PolicyReq []byte   // درخواست سیاست (رمزنگاری شده با pre-shared key) - فعلاً placeholder
	Timestamp int64    // مهر زمانی
	Nonce     [16]byte // برای جلوگیری از replay
}

type ClientHandshakePacket struct {
	Magic     [4]byte // برای تشخیص سریع (اختیاری)
	Handshake ClientHandshake
}

type ServerHandshake struct {
	PublicKey   [32]byte // کلید عمومی سرور
	PolicyGrant []byte   // اعطای سیاست (رمزنگاری شده) - فعلاً placeholder
}
