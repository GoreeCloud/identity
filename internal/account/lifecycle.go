package account

import (
	"errors"
	"fmt"
)

var (
	ErrUnknownState                 = errors.New("unknown account lifecycle state")
	ErrUnknownOperation             = errors.New("unknown account lifecycle operation")
	ErrPermanentDeletionConfirmation = errors.New("permanent account deletion requires explicit confirmation")
	ErrDeletedAccountTerminal       = errors.New("deleted account state is terminal")
)

type State string

const (
	StateActive      State = "active"
	StateDeactivated State = "deactivated"
	StateDeleted     State = "deleted"
)

type Operation string

const (
	OperationDeactivate      Operation = "deactivate"
	OperationReactivate      Operation = "reactivate"
	OperationPermanentDelete Operation = "permanent-delete"
)

type TransitionRequest struct {
	Current                     State
	Operation                   Operation
	PermanentDeletionConfirmed bool
}

func Transition(request TransitionRequest) (State, error) {
	if !request.Current.valid() {
		return "", fmt.Errorf("%w: %q", ErrUnknownState, request.Current)
	}
	if request.Current == StateDeleted {
		return StateDeleted, ErrDeletedAccountTerminal
	}

	switch request.Operation {
	case OperationDeactivate:
		if request.Current == StateDeactivated {
			return StateDeactivated, nil
		}
		return StateDeactivated, nil
	case OperationReactivate:
		if request.Current == StateActive {
			return StateActive, nil
		}
		return StateActive, nil
	case OperationPermanentDelete:
		if !request.PermanentDeletionConfirmed {
			return request.Current, ErrPermanentDeletionConfirmation
		}
		return StateDeleted, nil
	default:
		return request.Current, fmt.Errorf("%w: %q", ErrUnknownOperation, request.Operation)
	}
}

func (s State) valid() bool {
	switch s {
	case StateActive, StateDeactivated, StateDeleted:
		return true
	default:
		return false
	}
}
