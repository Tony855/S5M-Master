package app

import "testing"

func TestIsInternalSettingKey(t *testing.T) {
	internal := []string{
		"agent_token",
		"agent_machine_abc",
		"agent_mihomo_secret_abc",
		"agent_secret_abc",
		"agent_command_abc",
		"agent_command_result_abc",
		"agent_lastseen_abc",
		"agent_status_abc",
		"mihomo_secret_controller",
	}
	for _, key := range internal {
		if !isInternalSettingKey(key) {
			t.Errorf("expected %q to be internal", key)
		}
	}
	public := []string{"tun_enable", "subscribe_url", "sub_url", "theme"}
	for _, key := range public {
		if isInternalSettingKey(key) {
			t.Errorf("expected %q to remain a public setting", key)
		}
	}
}
