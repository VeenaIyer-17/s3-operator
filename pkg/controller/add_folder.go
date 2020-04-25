package controller

import (
	"github.com/advancecloud7374/s3-operator/pkg/controller/folder"
)

func init() {
	// AddToManagerFuncs is a list of functions to create controllers and add them to a manager.
	AddToManagerFuncs = append(AddToManagerFuncs, folder.Add)
}
