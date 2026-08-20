module github.com/quilzo/quilzo

go 1.27

// The toolchain is the entire supply chain here.
//
// go.mod has no require block, so the standard library is the only
// dependency this program has — which makes the Go release it is built
// with the whole of what a vulnerability scanner has to look at. Pinned to
// a floor rather than left to whatever is installed: govulncheck found
// eight reachable standard-library vulnerabilities on 1.26.4, all fixed in
// 1.26.6, and a bare "go 1.27" reads as 1.27.0 to a scanner.
//
// This project was pinned to 1.24 until August 2026. Go 1.24 reached end
// of life on 10 February 2026 and receives no security patches at all, so
// every released binary carried 29 known standard-library CVEs with no
// path to a fix. That is the cost of the zero-dependency argument being
// true: there is one dependency, and it has to be current.
toolchain go1.27.0
