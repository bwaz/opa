package server

import (
	"encoding/json"
	"fmt"
	"net"

	// opa/pb is a copy of policy-engine/infoblox_policy
	ibp "github.com/open-policy-agent/opa/pb"
	//ibp "github.com/Infoblox-CTO/policy-engine/infoblox_policy"

	log "github.com/Sirupsen/logrus"
	"github.com/open-policy-agent/opa/topdown"
	"golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

type ValidateMatch struct {
	ActionData string
	ActionType string
	Priority   int64
}

func (s *Server) Validate(server_ctx context.Context, in *ibp.Request) (*ibp.Response, error) {
	return s.grpcDataGet(server_ctx, in)
}

func (s *Server) grpcDataGet(ctx context.Context, in *ibp.Request) (*ibp.Response, error) {
	r := &ibp.Response{}
	r.Effect = ibp.Response_DENY

	var cId string
	inputs := make([]string, 0)
	for _, v := range in.Attributes {
		inputs = append(inputs, v.Id+`:"`+v.Value+`"`)
		if v.Id == "customer_id" {
			cId = v.Value
		}
	}
	path := stringPathToDataRef("opa/" + cId)
	input, nonGround, err := parseInput(inputs)

	//fmt.Println(input, path)

	if err != nil {
		return r, err
	}

	// Prepare for query.
	txn, err := s.store.NewTransaction(ctx)
	if err != nil {
		return r, err
	}
	defer s.store.Close(ctx, txn)

	compiler := s.Compiler()
	params := topdown.NewQueryParams(ctx, compiler, s.store, txn, input, path)

	// Execute query.
	qrs, err := topdown.Query(params)
	if err != nil {
		return r, err
	}
	if nonGround {
		return r, nil
		//return fmt.Sprintf("%s", newQueryResultSetV1(qrs)[0].result)

	}

	/*
		look for "match" in results and use the match with the highest priority
			"match": {

		    "RULE_298264": {
		        "action_data": "",
		        "action_type": "action_block",
		        "priority": 9
		    },
		    "RULE_311764": {
		        "action_data": "",
		        "action_type": "action_allow",
		        "priority": 22
		    }

		}
	*/
	if len(qrs) > 0 {
		bestMatch := &ValidateMatch{"", "", 0}
		matches := qrs[0].Result.(map[string]interface{})["match"]
		for _, val := range matches.(map[string]interface{}) {
			p, _ := val.(map[string]interface{})["priority"].(json.Number).Int64()
			if p > bestMatch.Priority {
				bestMatch.Priority = p
				bestMatch.ActionType = val.(map[string]interface{})["action_type"].(string)
				bestMatch.ActionData = val.(map[string]interface{})["action_data"].(string)
			}
		}

		// default to permit, override when blocked or redirected
		r.Effect = ibp.Response_PERMIT
		if bestMatch.ActionType == "action_block" {
			r.Effect = ibp.Response_DENY
		} else if bestMatch.ActionType == "action_redirect" {
			r.Effect = ibp.Response_DENY
			o := &ibp.Attribute{}
			o.Id = "redirect_to"
			o.Value = bestMatch.ActionData
			r.Obligation = append(r.Obligation, o)
		}
	}

	return r, nil

}

func (s *Server) GRPCLoop(servicePort string) error {
	verbose := false
	if servicePort == "" {
		servicePort = "0.0.0.0:5555"
	}

	if verbose {
		log.SetLevel(log.InfoLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}
	fmt.Println("Logging level: ", log.GetLevel())

	log.WithField("service_port", servicePort).Info("Opening service port")
	service, err := net.Listen("tcp", servicePort)
	if err != nil {
		return err
	}

	sGRPC := grpc.NewServer()
	ibp.RegisterPDPServer(sGRPC, s)
	log.Info("Serving requests...")
	sGRPC.Serve(service)

	return err
}
