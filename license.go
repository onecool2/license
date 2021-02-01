package license

import (
        "github.com/tjfoc/gmsm/sm2"
        "log"
        "bytes"
        "fmt"
        "os"
        "io/ioutil"
)

func GenerateKey(){
        priv, err := sm2.GenerateKey() // 生成密钥对
        if err != nil {         log.Fatal(err)
                log.Fatal(err)
        }
        fmt.Printf("私钥:%x\n\n\n\n", priv)
        fmt.Printf("公钥:%x\n\n\n\n", priv.Public())

        ok, err := sm2.WritePrivateKeytoPem("priv.pem", priv, nil) // 生成密钥文件
        if ok != true {
                log.Fatal(err)
        }
        pubKey, _ := priv.Public().(*sm2.PublicKey)
        ok, err = sm2.WritePublicKeytoPem("pub.pem", pubKey, nil) // 生成公钥文件
        if ok != true {
                log.Fatal(err)
        }
}

func LoadKey()(*sm2.PrivateKey, *sm2.PublicKey){
        privKey, err := sm2.ReadPrivateKeyFromPem("priv.pem", nil) // 读取密钥
        if err != nil {
                log.Fatal(err)
        }
        pubKey, err := sm2.ReadPublicKeyFromPem("pub.pem", nil) // 读取公钥
        if err != nil {
                log.Fatal(err)
        }
        return privKey, pubKey
}
/*
func GetLicenseContent(*sm2.PublicKey){

}
*/
func GenerateLicense(licenseStr string) {
        priv, _ := LoadKey()
        r,s,err := sm2.Sign(priv, []byte(licenseStr))
        if err != nil {
                log.Fatal(err)
        }
        license := []byte(licenseStr + r.String() + " " + s.String())
        err = ioutil.WriteFile("License", license, os.FileMode(0644))
        if err != nil {
                log.Fatal(err)
        }
}


func TestLicense(licenseStr string) {
        priv, err := sm2.GenerateKey() // 生成密钥对
        if err != nil {         log.Fatal(err)
                log.Fatal(err)
        }
        fmt.Printf("私钥:%x\n\n\n\n", priv)
        fmt.Printf("公钥:%x\n\n\n\n", priv.Public())
        msg := []byte(licenseStr)
        pub := &priv.PublicKey

        ok, err := sm2.WritePrivateKeytoPem("priv.pem", priv, nil) // 生成密钥文件
        if ok != true {
                log.Fatal(err)
        }
        pubKey, _ := priv.Public().(*sm2.PublicKey)
        ok, err = sm2.WritePublicKeytoPem("pub.pem", pubKey, nil) // 生成公钥文件
        if ok != true {
                log.Fatal(err)
        }

        ciphertxt, err := pub.Encrypt(msg)
        if err != nil {
                log.Fatal(err)
        }
        fmt.Printf("加密结果:%x\n",ciphertxt)
        plaintxt,err :=  priv.Decrypt(ciphertxt)
        if err != nil {
                log.Fatal(err)
        }
        fmt.Printf("原文:%s\n", plaintxt)
        if !bytes.Equal(msg,plaintxt){
                log.Fatal("原文不匹配")
        }

        r,s,err := sm2.Sign(priv, msg)
        if err != nil {
                log.Fatal(err)
        }
        isok := sm2.Verify(pub,msg,r,s)
        fmt.Printf("Verified: %v\n %x %x", isok, r, s)
}
