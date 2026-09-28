package account

import (
	"errors"
	"testing"
)

func TestDeactivateAndReactivateAreReversible(t *testing.T) {
	state, err := Transition(TransitionRequest{
		Current:   StateActive,
		Operation: OperationDeactivate,
	})
	if err != nil {
		t.Fatalf("deactivate error = %v", err)
	}
	if state != StateDeactivated {
		t.Fatalf("deactivate state = %q, want %q", state, StateDeactivated)
	}

	state, err = Transition(TransitionRequest{
		Current:   state,
		Operation: OperationReactivate,
	})
	if err != nil {
		t.Fatalf("reactivate error = %v", err)
	}
	if state != StateActive {
		t.Fatalf("reactivate state = %q, want %q", state, StateActive)
	}
}

func TestDeactivateAndReactivateAreIdempotent(t *testing.T) {
	tests := []struct {
		name      string
		request   TransitionRequest
		wantState State
	}{
		{
			name: "already deactivated",
			request: TransitionRequest{
				Current:   StateDeactivated,
				Operation: OperationDeactivate,
			},
			wantState: StateDeactivated,
		},
		{
			name: "already active",
			request: TransitionRequest{
				Current:   StateActive,
				Operation: OperationReactivate,
			},
			wantState: StateActive,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state, err := Transition(tc.request)
			if err != nil {
				t.Fatalf("Transition() error = %v", err)
			}
			if state != tc.wantState {
				t.Fatalf("state = %q, want %q", state, tc.wantState)
			}
		})
	}
}

func TestPermanentDeleteRequiresExplicitConfirmation(t *testing.T) {
	state, err := Transition(TransitionRequest{
		Current:   StateActive,
		Operation: OperationPermanentDelete,
	})
	if !errors.Is(err, ErrPermanentDeletionConfirmation) {
		t.Fatalf("Transition() error = %v, want ErrPermanentDeletionConfirmation", err)
	}
	if state != StateActive {
		t.Fatalf("state = %q, want unchanged %q", state, StateActive)
	}
}

func TestPermanentDeleteAcceptsActiveOrDeactivatedAccount(t *testing.T) {
	for _, state := range []State{StateActive, StateDeactivated} {
		t.Run(string(state), func(t *testing.T) {
			next, err := Transition(TransitionRequest{
				Current:                    state,
				Operation:                  OperationPermanentDelete,
				PermanentDeletionConfirmed: true,
			})
			if err != nil {
				t.Fatalf("Transition() error = %v", err)
			}
			if next != StateDeleted {
				t.Fatalf("state = %q, want %q", next, StateDeleted)
			}
		})
	}
}

func TestDeletedAccountIsTerminal(t *testing.T) {
	for _, operation := range []Operation{
		OperationDeactivate,
		OperationReactivate,
		OperationPermanentDelete,
	} {
		t.Run(string(operation), func(t *testing.T) {
			state, err := Transition(TransitionRequest{
				Current:                    StateDeleted,
				Operation:                  operation,
				PermanentDeletionConfirmed: true,
			})
			if !errors.Is(err, ErrDeletedAccountTerminal) {
				t.Fatalf("Transition() error = %v, want ErrDeletedAccountTerminal", err)
			}
			if state != StateDeleted {
				t.Fatalf("state = %q, want %q", state, StateDeleted)
			}
		})
	}
}

func TestUnknownStateAndOperationFailClosed(t *testing.T) {
	if _, err := Transition(TransitionRequest{
		Current:   State("unknown"),
		Operation: OperationDeactivate,
	}); !errors.Is(err, ErrUnknownState) {
		t.Fatalf("unknown state error = %v, want ErrUnknownState", err)
	}

	state, err := Transition(TransitionRequest{
		Current:   StateActive,
		Operation: Operation("logout"),
	})
	if !errors.Is(err, ErrUnknownOperation) {
		t.Fatalf("logout-like operation error = %v, want ErrUnknownOperation", err)
	}
	if state != StateActive {
		t.Fatalf("state = %q, want unchanged %q", state, StateActive)
	}
}
