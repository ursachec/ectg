package main

import (
	"math/rand"
	"regexp"
	"testing"
	"time"
)

func TestHostnameWithPayloadSimplestInvocation(t *testing.T) {
	rs := rand.NewSource(time.Now().UnixNano())
	r := rand.New(rs)

	hostname := "nosuchtokennonononononono.canarytokens.com"
	res := hostnameWithPayload(hostname, "", r)
	want := hostname
	if res != want {
		t.Fatalf("strings not equal. res: `%s` | want: `%s`", res, want)
	}
}

func TestHostnameWithPayload(t *testing.T) {
	testCases := []struct {
		hostname string
		payload  string
		regexStr string
	}{
		{"nosuchtokennonononononono.canarytokens.com", "", "nosuchtokennonononononono.canarytokens.com"},
		{"nosuchtokennonononononono.canarytokens.com", "whoami", "^[a-zA-Z0-9]+\\.G[0-9][0-9]\\.nosuchtokennonononononono.canarytokens.com"},

		//$ (export STR=$(python3 -c "print('dot'.join(str(i) for i in range(0, 10)), end='')") && export B32=$(echo $STR|base32 -w 0|tr -d =) && echo $STR $(echo $STR|wc -c) $B32 $(echo $B32|wc -c))
		//0dot1dot2dot3dot4dot5dot6dot7dot8dot9 38 GBSG65BRMRXXIMTEN52DGZDPOQ2GI33UGVSG65BWMRXXIN3EN52DQZDPOQ4QU 62
		{"nosuchtokennonononononono.canarytokens.com", "0dot1dot2dot3dot4dot5dot6dot7dot8dot9", "^[a-zA-Z0-9]+\\.G[0-9][0-9]\\.nosuchtokennonononononono.canarytokens.com"},

		//$ (export STR=$(python3 -c "print('dot'.join(str(i) for i in range(0, 16)), end='')") && export B32=$(echo $STR|base32 -w 0|tr -d =) && echo $STR $(echo $STR|wc -c) $B32 $(echo $B32|wc -c))
		//0dot1dot2dot3dot4dot5dot6dot7dot8dot9dot10dot11dot12dot13dot14dot15 68 GBSG65BRMRXXIMTEN52DGZDPOQ2GI33UGVSG65BWMRXXIN3EN52DQZDPOQ4WI33UGEYGI33UGEYWI33UGEZGI33UGEZWI33UGE2GI33UGE2QU 110
		{"nosuchtokennonononononono.canarytokens.com", "0dot1dot2dot3dot4dot5dot6dot7dot8dot9dot10dot11dot12dot13dot14dot15", "^[a-zA-Z0-9]+\\.[a-zA-Z0-9]+\\.G[0-9][0-9]\\.nosuchtokennonononononono.canarytokens.com"},

		//$ (export STR=$(python3 -c "print('dot'.join(str(i) for i in range(0, 20)), end='')") && export B32=$(echo $STR|base32 -w 0|tr -d =) && echo $STR $(echo $STR|wc -c) $B32 $(echo $B32|wc -c))
		//0dot1dot2dot3dot4dot5dot6dot7dot8dot9dot10dot11dot12dot13dot14dot15dot16dot17dot18dot19 88 GBSG65BRMRXXIMTEN52DGZDPOQ2GI33UGVSG65BWMRXXIN3EN52DQZDPOQ4WI33UGEYGI33UGEYWI33UGEZGI33UGEZWI33UGE2GI33UGE2WI33UGE3GI33UGE3WI33UGE4GI33UGE4QU 142
		{"nosuchtokennonononononono.canarytokens.com", "0dot1dot2dot3dot4dot5dot6dot7dot8dot9dot10dot11dot12dot13dot14dot15dot16dot17dot18dot19", "^[a-zA-Z0-9]+\\.[a-zA-Z0-9]+\\.[a-zA-Z0-9]+\\.G[0-9][0-9]\\.nosuchtokennonononononono.canarytokens.com"},

		//$ (export STR=$(python3 -c "print('dot'.join(str(i) for i in range(0, 35)), end='')") && export B32=$(echo $STR|base32 -w 0|tr -d =) && echo $STR $(echo $STR|wc -c) $B32 $(echo $B32|wc -c))
		//0dot1dot2dot3dot4dot5dot6dot7dot8dot9dot10dot11dot12dot13dot14dot15dot16dot17dot18dot19dot20dot21dot22dot23dot24dot25dot26dot27dot28dot29dot30dot31dot32dot33dot34 163 GBSG65BRMRXXIMTEN52DGZDPOQ2GI33UGVSG65BWMRXXIN3EN52DQZDPOQ4WI33UGEYGI33UGEYWI33UGEZGI33UGEZWI33UGE2GI33UGE2WI33UGE3GI33UGE3WI33UGE4GI33UGE4WI33UGIYGI33UGIYWI33UGIZGI33UGIZWI33UGI2GI33UGI2WI33UGI3GI33UGI3WI33UGI4GI33UGI4WI33UGMYGI33UGMYWI33UGMZGI33UGMZWI33UGM2AU 262
		{"nosuchtokennonononononono.canarytokens.com", "0dot1dot2dot3dot4dot5dot6dot7dot8dot9dot10dot11dot12dot13dot14dot15dot16dot17dot18dot19dot20dot21dot22dot23dot24dot25dot26dot27dot28dot29dot30dot31dot32dot33dot34", "^[a-zA-Z0-9]+\\.[a-zA-Z0-9]+\\.[a-zA-Z0-9]+\\.[a-zA-Z0-9]+\\.G[0-9][0-9]\\.nosuchtokennonononononono.canarytokens.com"},
	}

	maxTotalLength := 253
	rs := rand.NewSource(41414141)
	r := rand.New(rs)

	for _, testCase := range testCases {
		res := hostnameWithPayload(testCase.hostname, testCase.payload, r)
		matched, _ := regexp.MatchString(testCase.regexStr, res)
		if !matched {
			t.Errorf("Result did not match regex. res `%s`, regex: `%s`, hostname: `%s`, payload: `%s`", res, testCase.regexStr, testCase.hostname, testCase.payload)
		}
		if len(res) > maxTotalLength {
			t.Errorf("Result string larger than expected max length. res: `%s`, hostname: `%s`, payload: `%s`", res, testCase.hostname, testCase.payload)
		}
	}
}
