package passwordstore

import (
	"context"
	"fmt"
	"io/ioutil"
	"regexp"

	"github.com/blang/semver"
	"github.com/gopasspw/gopass/pkg/action"
	_ "github.com/gopasspw/gopass/pkg/backend/storage"
	gpConfig "github.com/gopasspw/gopass/pkg/config"
)

func Decrypt(path string) (content []byte, err error) {
	act, err := initGopass()
	if err != nil {
		err = fmt.Errorf("failed to create a gopass action: %s", err)
		return
	}
	sec, err := act.Store.Get(context.Background(), path)
	if err != nil {
		err = fmt.Errorf("failed to get secret at %s: %s", path, err)
		return
	}

	body, err := sec.Bytes()
	if err != nil {
		err = fmt.Errorf("failed to retrieve secret: %s", err)
		return
	}

	re := regexp.MustCompile(`(?ms)---(.*)`)
	content = re.Find(body)
	if content == nil {
		err = fmt.Errorf("found empty content")
	}
	return
}

func DecryptToFile(path string) (unsealedSecretPath string, err error) {
	value, err := Decrypt(path)
	if err != nil {
		return
	}

	tmpFile, err := ioutil.TempFile("", "secret")
	if err != nil {
		return
	}
	defer tmpFile.Close()

	err = ioutil.WriteFile(tmpFile.Name(), value, 0644)
	if err != nil {
		return
	}
	unsealedSecretPath = tmpFile.Name()
	return
}

func initGopass() (act *action.Action, err error) {
	gpc := gpConfig.Load()
	ctx := context.Background()
	act, err = action.New(ctx, gpc, semver.Version{})
	if err != nil {
		return nil, fmt.Errorf("failed to create new action: %s", err)
	}

	if ok, err := act.Store.Initialized(ctx); !ok {
		return nil, fmt.Errorf("password-store uninitialized: %s", err)
	}
	return
}
