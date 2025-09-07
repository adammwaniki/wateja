//services/user/cmd/main.go
package main

import (
	"log"
	"net"
	"os"

	"github.com/adammwaniki/wateja/services/user/api"
	"github.com/adammwaniki/wateja/services/user/internal/service"
	"github.com/adammwaniki/wateja/services/user/internal/store"
	"github.com/adammwaniki/wateja/services/user/internal/types"
	_ "github.com/joho/godotenv/autoload"
	"google.golang.org/grpc"
)

var (
	grpcAddr = os.Getenv("USER_GRPC_ADDR")
)

func main() {

	// Initialize dependencies
	store, err := store.NewStore(os.Getenv("DB_DSN"))
	if err != nil {
		log.Fatal("Store initialization failed: ", err)
	}

	// Initialise service business logic
	svc := service.NewService(store)

	// Start gRPC server 
	startGRPCServer(svc)
}

func startGRPCServer(svc types.UserService) {
	lis, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		log.Fatal("gRPC listener failed: ", err)
	}
	defer lis.Close()

	grpcServer := grpc.NewServer()
	api.NewGRPCHandler(grpcServer, svc)

	log.Printf("Starting gRPC server on %s", grpcAddr)
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatal("gRPC server failed: ", err)
	}
}

