package ssh


import (
	"log"
	"os"
	"bytes"
	"golang.org/x/crypto/ssh"
)

/*
func RunSSHCommand(host string, cmd string) (string, error) {

	log.Printf("-------- CMD on %s -------------", host)
	log.Println("\n"+cmd)
	log.Println("------- /CMD ----------")
	return "", nil
}

*/


func RunSSHCommand(addr, user, keyPath, cmd string) (string, string, error) {

	log.Printf("Connecting via SSH to:\n")
	log.Printf("   Address: %s\n",addr)
	log.Printf("   User: %s\n",user)
	log.Printf("   keyPath: %s\n",keyPath)
	log.Printf("   cmd: \n%s\n", cmd)

	if _, err := os.Stat(keyPath); err != nil {
		return "", "", err
	}


	key, _ := os.ReadFile(keyPath)
	signer, _ := ssh.ParsePrivateKey(key)

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return "", "", err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", "", err
	}
	defer session.Close()

	var out, errOut bytes.Buffer
	session.Stdout = &out
	session.Stderr = &errOut

	err = session.Run(cmd)
	return out.String(), errOut.String(), err
}
