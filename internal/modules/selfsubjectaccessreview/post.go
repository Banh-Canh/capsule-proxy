// Copyright 2020-2025 Project Capsule Authors
// SPDX-License-Identifier: Apache-2.0

package selfsubjectaccessreview

import (
	"context"
	"fmt"
	"slices"

	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcapsule/capsule-proxy/internal/modules"
	"github.com/projectcapsule/capsule-proxy/internal/request"
	"github.com/projectcapsule/capsule-proxy/internal/tenant"
)

type post struct {
	reader client.Reader
	writer client.Writer
}

func Post(reader client.Reader, writer client.Writer) modules.Module {
	return &post{
		reader: reader,
		writer: writer,
	}
}

func (p post) GroupVersionKind() schema.GroupVersionKind {
	return schema.GroupVersionKind{
		Group:   "authorization.k8s.io",
		Version: "v1",
		Kind:    "SelfSubjectAccessReview",
	}
}

func (p post) GroupKind() schema.GroupKind {
	return schema.GroupKind{
		Group: "authorization.k8s.io",
		Kind:  "SelfSubjectAccessReview",
	}
}

func (p post) Path() string {
	return "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
}

func (p post) Methods() []string {
	return []string{"POST"}
}

func (p post) Handle(proxyTenants []*tenant.ProxyTenant, proxyRequest request.Request) (selector labels.Selector, err error) {
	return nil, nil
}

func HandleSelfSubjectAccessReview(
	ctx context.Context,
	proxyTenants []*tenant.ProxyTenant,
	username string,
	groups []string,
	sar *authorizationv1.SelfSubjectAccessReview,
	writer client.Writer,
) error {
	resourceAttrs := sar.Spec.ResourceAttributes

	if resourceAttrs == nil {
		// Non-resource attributes are not handled by this module, let the request pass.
		return nil
	}

	if resourceAttrs.Namespace != "" {
		requestedNS := resourceAttrs.Namespace
		isTenantNamespace := false
		for _, tenant := range proxyTenants {
			if slices.Contains(tenant.Tenant.Status.Namespaces, requestedNS) {
				isTenantNamespace = true
			}
			if isTenantNamespace {
				break
			}
		}

		// If the namespace belongs to the user's tenants, perform a real SubjectAccessReview.
		if isTenantNamespace {
			sarCheck := &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User:               username,
					Groups:             groups,
					ResourceAttributes: resourceAttrs,
				},
			}

			if err := writer.Create(ctx, sarCheck); err == nil {
				sar.Status.Allowed = sarCheck.Status.Allowed
				sar.Status.Reason = sarCheck.Status.Reason
			} else {
				sar.Status.Allowed = false
				sar.Status.Reason = "Failed to perform SubjectAccessReview against the API server."
			}
		} else {
			// The namespace is not managed by the user's tenants, so deny access.
			sar.Status.Allowed = false
			sar.Status.Reason = fmt.Sprintf("Access denied: namespace %q is not one of your tenant namespaces", requestedNS)
		}

		return nil
	}

	// We allow the check to succeed if the user is a member of any tenant,
	// regardless of whether the tenant has existing namespaces or resources.
	// This decouples the permission check from the existence of resources.
	if len(proxyTenants) > 0 {
		sar.Status.Allowed = true
		sar.Status.Reason = "Allowed because the user is a member of one or more tenants."
	} else {
		sar.Status.Allowed = false
		sar.Status.Reason = "Denied because the user is not a member of any tenant."
	}

	return nil
}
