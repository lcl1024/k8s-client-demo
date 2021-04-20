package main

import (
	"context"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"os"
)

func main() {
	configBytes, err := os.ReadFile("config.yaml")
	if err != nil {
		panic(err.Error())
	}
	kubeConfig, err := clientcmd.RESTConfigFromKubeConfig(configBytes)
	if err != nil {
		panic(err.Error())
	}
	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		panic(err.Error())
	}

	nodeList, err := clientset.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}
	if len(nodeList.Items) <= 0 {
		panic("not found node")
	}
	for _, i := range nodeList.Items {
		fmt.Println(i.Name)
	}
}
