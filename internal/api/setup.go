package api

import (
	"context"
	"errors"

	"github.com/danielgtaylor/huma/v2"

	oidcclient "github.com/voidgrid/voidgrid-secrets/internal/auth/oidc"
	"github.com/voidgrid/voidgrid-secrets/internal/setup"
)

// SetupHandler implements the first-run setup wizard's HTTP operations.
type SetupHandler struct {
	wizard       *setup.Wizard
	oidcProvider *oidcclient.Provider
}

// NewSetupHandler returns a SetupHandler backed by w. A successful OIDC
// setup installs the newly built client into oidcProvider, so login works
// immediately without waiting for a server restart.
func NewSetupHandler(w *setup.Wizard, oidcProvider *oidcclient.Provider) *SetupHandler {
	return &SetupHandler{wizard: w, oidcProvider: oidcProvider}
}

// RegisterSetup registers the setup wizard operations on api.
func RegisterSetup(api huma.API, h *SetupHandler) {
	huma.Register(api, huma.Operation{
		OperationID: "setup-status",
		Method:      "GET",
		Path:        "/setup/status",
		Summary:     "Check whether the first-run setup wizard has completed",
		Tags:        []string{"setup"},
	}, h.Status)

	huma.Register(api, huma.Operation{
		OperationID: "setup-password-init",
		Method:      "POST",
		Path:        "/setup/password/init",
		Summary:     "Create the first admin account and begin TOTP enrollment",
		Tags:        []string{"setup"},
	}, h.InitPassword)

	huma.Register(api, huma.Operation{
		OperationID: "setup-password-confirm",
		Method:      "POST",
		Path:        "/setup/password/confirm",
		Summary:     "Confirm TOTP enrollment and complete setup",
		Tags:        []string{"setup"},
	}, h.ConfirmPassword)

	huma.Register(api, huma.Operation{
		OperationID: "setup-oidc",
		Method:      "POST",
		Path:        "/setup/oidc",
		Summary:     "Configure OIDC as the deployment's auth method and complete setup",
		Tags:        []string{"setup"},
	}, h.SetupOIDC)
}

// EmptyInput is used by operations that take no parameters or body.
type EmptyInput struct{}

// SetupStatusOutput reports whether the wizard has completed.
type SetupStatusOutput struct {
	Body struct {
		Complete bool `json:"complete"`
	}
}

// Status reports whether setup has already completed.
func (h *SetupHandler) Status(ctx context.Context, _ *EmptyInput) (*SetupStatusOutput, error) {
	complete, err := h.wizard.IsComplete(ctx)
	if err != nil {
		return nil, huma.Error500InternalServerError("internal error", err)
	}
	out := &SetupStatusOutput{}
	out.Body.Complete = complete
	return out, nil
}

// InitPasswordSetupInput carries the first admin account's credentials.
type InitPasswordSetupInput struct {
	Body struct {
		SetupToken string `json:"setup_token" minLength:"1" doc:"The setup token printed in the server log at startup"`
		Username   string `json:"username" minLength:"1"`
		Password   string `json:"password" minLength:"14"`
	}
}

// InitPasswordSetupOutput carries the generated TOTP secret and
// provisioning URI to present as a QR code.
type InitPasswordSetupOutput struct {
	Body struct {
		Secret          string `json:"secret"`
		ProvisioningURI string `json:"provisioning_uri"`
	}
}

// InitPassword creates the first admin account and begins TOTP enrollment.
func (h *SetupHandler) InitPassword(ctx context.Context, in *InitPasswordSetupInput) (*InitPasswordSetupOutput, error) {
	secret, uri, err := h.wizard.InitPasswordSetup(ctx, in.Body.SetupToken, in.Body.Username, in.Body.Password)
	if err != nil {
		return nil, mapSetupErr(err)
	}
	out := &InitPasswordSetupOutput{}
	out.Body.Secret = secret
	out.Body.ProvisioningURI = uri
	return out, nil
}

// ConfirmPasswordSetupInput carries the admin's first TOTP code.
type ConfirmPasswordSetupInput struct {
	Body struct {
		SetupToken string `json:"setup_token" minLength:"1" doc:"The setup token printed in the server log at startup"`
		Username   string `json:"username"`
		Code       string `json:"code"`
	}
}

// ConfirmPasswordSetupOutput carries the one-time batch of recovery codes
// issued on setup completion.
type ConfirmPasswordSetupOutput struct {
	Body struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
}

// ConfirmPassword validates the admin's TOTP code and completes setup.
func (h *SetupHandler) ConfirmPassword(ctx context.Context, in *ConfirmPasswordSetupInput) (*ConfirmPasswordSetupOutput, error) {
	codes, err := h.wizard.ConfirmPasswordSetup(ctx, in.Body.SetupToken, in.Body.Username, in.Body.Code)
	if err != nil {
		return nil, mapSetupErr(err)
	}
	out := &ConfirmPasswordSetupOutput{}
	out.Body.RecoveryCodes = codes
	return out, nil
}

// SetupOIDCInput carries the OIDC provider configuration. RedirectURI must
// be the exact callback URL registered with the provider.
type SetupOIDCInput struct {
	Body struct {
		SetupToken   string `json:"setup_token" minLength:"1" doc:"The setup token printed in the server log at startup"`
		Issuer       string `json:"issuer"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RedirectURI  string `json:"redirect_uri"`
	}
}

// SetupOIDCOutput is empty: success is signaled by a 2xx status.
type SetupOIDCOutput struct{}

// SetupOIDC configures OIDC as the deployment's auth method and completes
// setup. It validates the issuer by actually performing OIDC discovery
// before storing anything - failing fast on a bad issuer here, at setup
// time, beats silently storing a config that can never work.
func (h *SetupHandler) SetupOIDC(ctx context.Context, in *SetupOIDCInput) (*SetupOIDCOutput, error) {
	// Checked before discovery, so nobody without the token can make this
	// server fetch an arbitrary URL.
	if err := h.wizard.CheckSetupToken(ctx, in.Body.SetupToken); err != nil {
		return nil, mapSetupErr(err)
	}
	client, err := oidcclient.New(ctx, oidcclient.Config{
		Issuer:       in.Body.Issuer,
		ClientID:     in.Body.ClientID,
		ClientSecret: in.Body.ClientSecret,
		RedirectURI:  in.Body.RedirectURI,
	})
	if err != nil {
		return nil, huma.Error400BadRequest("failed to discover OIDC issuer - check the issuer URL and that this server can reach it", err)
	}

	if err := h.wizard.SetupOIDC(ctx, in.Body.SetupToken, in.Body.Issuer, in.Body.ClientID, in.Body.ClientSecret, in.Body.RedirectURI); err != nil {
		return nil, mapSetupErr(err)
	}

	h.oidcProvider.Set(client)
	return &SetupOIDCOutput{}, nil
}

func mapSetupErr(err error) error {
	switch {
	case errors.Is(err, setup.ErrInvalidSetupToken):
		return huma.Error403Forbidden("invalid setup token - use the one printed in the server log at startup")
	case errors.Is(err, setup.ErrAlreadyComplete):
		return huma.Error409Conflict("setup already completed", err)
	case errors.Is(err, setup.ErrAdminPending):
		return huma.Error409Conflict("an admin account is already pending confirmation", err)
	case errors.Is(err, setup.ErrInvalidCode):
		return huma.Error400BadRequest("invalid TOTP code", err)
	default:
		return huma.Error500InternalServerError("internal error", err)
	}
}
