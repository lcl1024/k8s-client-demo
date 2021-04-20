package main

import (
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	kubeConfig, err := clientcmd.BuildConfigFromFlags("", "config.yaml")
	if err != nil {
		panic(err.Error())
	}
	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		panic(err.Error())
	}

	nodeList, err := clientset.CoreV1().Nodes().List(metav1.ListOptions{})
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
