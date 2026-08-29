//go:build !linux

package action

import "errors"

type unsupportedProcessController struct{}

func NewSystemProcessController() ProcessController { return unsupportedProcessController{} }
func (unsupportedProcessController) Inspect(int) (ProcessRuntimeIdentity, error) {
	return ProcessRuntimeIdentity{}, errors.New("process suspension is supported only on Linux")
}
func (unsupportedProcessController) Stop(int) error {
	return errors.New("process suspension is supported only on Linux")
}
func (unsupportedProcessController) Continue(int) error {
	return errors.New("process suspension is supported only on Linux")
}
