package bccsp

const (
	SM2 = "SM2"
	SM3 = "SM3"
	SM4 = "SM4"
)

type SM2KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SM2KeyGenOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type SM2PublicKeyImportOpts struct {
	Temporary bool
}

func (opts *SM2PublicKeyImportOpts) Algorithm() string {
	return SM2
}

func (opts *SM2PublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type SM4KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SM4KeyGenOpts) Algorithm() string {
	return SM4
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM4KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type SM4KeyImportOpts struct {
	Temporary bool
}

func (opts *SM4KeyImportOpts) Algorithm() string {
	return SM4
}

func (opts *SM4KeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}
