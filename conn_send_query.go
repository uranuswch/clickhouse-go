package clickhouse

import (
	"fmt"
	"log/slog"

	"github.com/ClickHouse/clickhouse-go/v2/lib/proto"
)

// Connection::sendQuery
// https://github.com/ClickHouse/ClickHouse/blob/master/src/Client/Connection.cpp
func (c *connect) sendQuery(body string, o *QueryOptions) error {
	c.logger.Debug("sending query",
		slog.String("compression", c.compression.String()),
		slog.String("query", body))

	// Resolve sign function: context-level overrides connection-level
	querySettings := o.settings
	if signFunc := c.resolveSignFunc(o); signFunc != nil {
		token, err := signFunc(body)
		if err != nil {
			return fmt.Errorf("failed to sign query: %w", err)
		}
		// Clone settings to avoid mutating the original map
		querySettings = make(Settings, len(o.settings)+1)
		for k, v := range o.settings {
			querySettings[k] = v
		}
		querySettings["SQL_x_auth_token"] = CustomSetting{Value: token}
		c.logger.Debug("query signed with JWS token")
	}

	c.buffer.PutByte(proto.ClientQuery)
	q := proto.Query{
		ClientTCPProtocolVersion: ClientTCPProtocolVersion,
		ClientName:               c.opt.ClientInfo.Append(o.clientInfo).String(),
		ClientVersion:            proto.Version{ClientVersionMajor, ClientVersionMinor, ClientVersionPatch}, //nolint:govet
		ID:                       o.queryID,
		Body:                     body,
		Span:                     o.span,
		QuotaKey:                 o.quotaKey,
		Compression:              c.compression != CompressionNone,
		InitialAddress:           c.conn.LocalAddr().String(),
		Settings:                 c.settings(querySettings),
		Parameters:               parametersToProtoParameters(o.parameters),
	}
	if err := q.Encode(c.buffer, c.revision); err != nil {
		return err
	}
	for _, table := range o.external {
		if err := c.sendData(table.Block(), table.Name()); err != nil {
			return err
		}
	}
	if err := c.sendData(proto.NewBlock(), ""); err != nil {
		return err
	}
	return c.flush()
}

func (c *connect) resolveSignFunc(o *QueryOptions) func(string) (string, error) {
	if o.signFunc != nil {
		return o.signFunc
	}
	return c.opt.SignFunc
}

func parametersToProtoParameters(parameters Parameters) (s proto.Parameters) {
	for k, v := range parameters {
		s = append(s, proto.Parameter{
			Key:   k,
			Value: v,
		})
	}

	return s
}
