# .NET NegotiateStream Protocol for Golang

This library implements a simple `net.Conn` abstraction for NNS authenticated streams.

It currently supports NTLMSSP as an authentication mechanism.

```golang
ntlmsspClient, err := ntlmssp.NewClient(ntlmssp.SetCompatibilityLevel(1), ntlmssp.SetUserInfo("user01", "password"))
if err != nil {
    return nil, err
}
nnsConn, err := nns.DialNTLMSSP("127.0.0.1:9380", ntlmsspClient, 5*time.Second)
if err != nil {
    return nil, err
}
```