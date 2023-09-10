package api

import (
	"context"
	"errors"
	"log"

	pb "github.com/lazybark/go-testing-authservice/pkg/api/grpc"
	"github.com/lazybark/go-testing-authservice/pkg/api/logic"
	"github.com/lazybark/go-testing-authservice/pkg/api/resp"
	"github.com/lazybark/go-testing-authservice/pkg/sec"
	"google.golang.org/grpc/peer"
)

func (s *Server) RegisterUser(ctx context.Context, in *pb.RegisterUserRequest) (*pb.GeneralReply, error) {
	data := logic.UserRegData{
		Login:     in.Login,
		Password:  in.Password,
		FirstName: in.FirstName,
		LastName:  in.LastName,
		Email:     in.Email,
	}

	err := logic.UserReg(data, s.ds)
	if err != nil {
		if errors.As(err, new(logic.LogicError)) {
			return &pb.GeneralReply{Success: false, Status: 200, Response: err.Error()}, nil
		}

		log.Println(err)
		return &pb.GeneralReply{Success: false, Status: 500, Response: resp.ErrInternalMessage}, nil
	}

	return &pb.GeneralReply{Success: true, Status: 200, Response: resp.RespOKMessage}, nil
}

func (s *Server) Login(ctx context.Context, in *pb.LoginRequest) (*pb.AuthTokenReply, error) {
	data := logic.UserLoginData{
		Login:    in.Login,
		Password: in.Password,
	}

	addr := ""
	p, ok := peer.FromContext(ctx)
	if ok {
		addr = p.Addr.String()
	}

	t, err := logic.UserLogin(data, s.ds, addr, s.maxWrongLogins, s.jwtSecret)
	if err != nil {
		if errors.As(err, new(logic.LogicError)) {
			return &pb.AuthTokenReply{Success: false, Status: 200, Response: err.Error()}, nil
		}

		log.Println(err)
		return &pb.AuthTokenReply{Success: false, Status: 500, Response: resp.ErrInternalMessage}, nil
	}

	return &pb.AuthTokenReply{Success: true, Status: 200, Response: resp.RespOKMessage, AuthToken: &pb.AuthTokenReply_AuthToken{
		AuthToken:    t.AuthToken,
		RefreshToken: t.RefreshToken,
	}}, nil
}

func (s *Server) CheckToken(ctx context.Context, in *pb.TokenRequest) (*pb.GeneralReply, error) {
	data := logic.TokenData{
		Token: in.Token,
	}

	ok, err := logic.TokenCheck(data.Token, s.jwtSecret)
	if err != nil {
		if errors.As(err, new(logic.LogicError)) || errors.As(err, new(sec.SecurityError)) {
			return &pb.GeneralReply{Success: false, Status: 200, Response: err.Error()}, nil
		}

		log.Println(err)
		return &pb.GeneralReply{Success: false, Status: 500, Response: resp.ErrInternalMessage}, nil
	}

	return &pb.GeneralReply{Success: true, Status: 200, Response: ok}, nil
}

func (s *Server) RefreshToken(ctx context.Context, in *pb.TokenRequest) (*pb.AuthTokenReply, error) {
	data := logic.TokenData{
		Token: in.Token,
	}

	t, err := logic.TokenGet(data.Token, s.jwtSecret)
	if err != nil {
		if errors.As(err, new(logic.LogicError)) || errors.As(err, new(sec.SecurityError)) {
			return &pb.AuthTokenReply{Success: false, Status: 200, Response: err.Error()}, nil
		}

		log.Println(err)
		return &pb.AuthTokenReply{Success: false, Status: 500, Response: resp.ErrInternalMessage}, nil
	}

	return &pb.AuthTokenReply{Success: true, Status: 200, Response: resp.RespOKMessage, AuthToken: &pb.AuthTokenReply_AuthToken{
		AuthToken:    t.AuthToken,
		RefreshToken: t.RefreshToken,
	}}, nil
}
