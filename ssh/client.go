package ssh


import (
	"log"
	"os"
//	"bytes"
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




func RunSSHCommand(addr, user, keyPath, cmd string) (*SessionReturn, error) {

	var sessionRet SessionReturn

	log.Printf("Connecting via SSH to:\n")
	log.Printf("   Address: %s\n",addr)
	log.Printf("   User: %s\n",user)
	log.Printf("   keyPath: %s\n",keyPath)
	log.Printf("   cmd: \n%s\n", cmd)

	if _, err := os.Stat(keyPath); err != nil {
		return nil, err
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
		return nil, err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()

//	var out, errOut bytes.Buffer
//	var bytes.Buffer
	session.Stdout = &sessionRet.StdOut
	session.Stderr = &sessionRet.StdErr
	err = session.Run(cmd)



	log.Println("\n",session.Stdout)
	log.Println("\n",session.Stderr)

	if err != nil {
		log.Printf("ERROR SSH : %v",err)
		return nil, err
	}


	return &sessionRet, nil
}
