package checkcli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/witkitlab/witshield/internal/ai"
	"github.com/witkitlab/witshield/internal/domain"
)

// AIConfigFromEnv reads the user's own model endpoint. Nothing is sent
// anywhere unless all three of base URL, key and model are set.
//
//	WITSHIELD_AI_BASE_URL  e.g. https://api.deepseek.com/v1
//	WITSHIELD_AI_API_KEY
//	WITSHIELD_AI_MODEL     e.g. deepseek-chat
//	WITSHIELD_AI_PROTOCOL  openai_chat (default) | openai_responses | anthropic_messages
func AIConfigFromEnv() (ai.Config, error) {
	cfg := ai.Config{
		Protocol: domain.AIProtocol(strings.TrimSpace(os.Getenv("WITSHIELD_AI_PROTOCOL"))),
		BaseURL:  strings.TrimSpace(os.Getenv("WITSHIELD_AI_BASE_URL")),
		APIKey:   strings.TrimSpace(os.Getenv("WITSHIELD_AI_API_KEY")),
		Model:    strings.TrimSpace(os.Getenv("WITSHIELD_AI_MODEL")),
	}
	if cfg.Protocol == "" {
		cfg.Protocol = domain.AIProtocolOpenAIChat
	}
	if cfg.BaseURL == "" || cfg.APIKey == "" || cfg.Model == "" {
		return cfg, errors.New("missing AI configuration")
	}
	return cfg, nil
}

const aiHelp = `还没有配置大模型。巡御不内置任何密钥，用你自己的 API，例如 DeepSeek：

  export WITSHIELD_AI_BASE_URL=https://api.deepseek.com/v1
  export WITSHIELD_AI_API_KEY=你的密钥
  export WITSHIELD_AI_MODEL=deepseek-chat
  witshield check --ai

通义千问、豆包、Kimi 等 OpenAI 兼容接口同理；Anthropic 接口另设 WITSHIELD_AI_PROTOCOL=anthropic_messages。
发送给模型的只有问题标题、等级和简短证据，不包含密码、密钥或文件内容。`

// AIPrompt builds the minimal, redacted context sent to the model.
func AIPrompt(r domain.Report) []ai.Message {
	var b strings.Builder
	fmt.Fprintf(&b, "安全分 %d/100。发现的问题：\n", r.Score)
	for _, f := range Sorted(r.Findings) {
		a := AdviceFor(f)
		fmt.Fprintf(&b, "- [%s] %s（证据：%s）\n", severityLabel[f.Severity], a.Title, truncate(f.Evidence, 160))
	}
	if len(r.Findings) == 0 {
		b.WriteString("- 无\n")
	}
	return []ai.Message{
		{Role: "system", Content: "你是一位耐心的服务器安全顾问，读者是管理自己 VPS 的个人开发者，不是安全专家。用简体中文回答，300 字以内。先用一句话总结这台服务器的整体情况；再按先后顺序说最该处理的 3 件事，每件说清楚不处理会怎样、大概要花多久；最后提醒一个容易被忽略的点（例如云服务器安全组、备份）。不要编造报告里没有的问题，不确定的地方明确说不确定。不要给出会导致锁死登录的命令。"},
		{Role: "user", Content: b.String()},
	}
}

// Explain asks the user's model to explain the report.
func Explain(ctx context.Context, cfg ai.Config, r domain.Report) (string, error) {
	client, err := ai.New(cfg)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	return client.ChatWithOutputLimit(ctx, AIPrompt(r), 1200)
}
