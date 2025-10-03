// Copyright 2020-2025 Project Capsule Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-logr/logr"
	authorizationv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcapsule/capsule-proxy/internal/modules/selfsubjectaccessreview"
	"github.com/projectcapsule/capsule-proxy/internal/request"
	"github.com/projectcapsule/capsule-proxy/internal/tenant"
	server "github.com/projectcapsule/capsule-proxy/internal/webserver/errors"
)

type SelfSubjectAccessReviewFunc func(ctx context.Context, username string, groups []string) ([]*tenant.ProxyTenant, error)

func CheckSelfSubjectAccessReviewMiddleware(
	writer client.Writer,
	reader client.Reader,
	log logr.Logger,
	usernameClaimField string,
	authTypes []request.AuthType,
	ignoredImpersonationGroups []string,
	impersonationGroupsRegexp *regexp.Regexp,
	skipImpersonationReview bool,
	getTenantsFunc SelfSubjectAccessReviewFunc,
	fallbackHandler http.HandlerFunc,
) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check if this is a SelfSubjectAccessReview request
			if !isSelfSubjectAccessReviewRequest(r) {
				next.ServeHTTP(w, r)
				return
			}

			contentType := r.Header.Get("Content-Type")
			if !strings.Contains(contentType, "application/json") &&
			   !strings.Contains(contentType, "application/vnd.kubernetes.protobuf") {
				next.ServeHTTP(w, r)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				server.HandleError(w, err, "failed to read request body")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))

			if len(body) == 0 {
				server.HandleError(w, err, "empty request body for SelfSubjectAccessReview")
				return
			}

			var sar authorizationv1.SelfSubjectAccessReview

			if strings.Contains(contentType, "application/json") {
				if err := json.Unmarshal(body, &sar); err != nil {
					server.HandleError(w, err, "failed to parse SelfSubjectAccessReview request")
					return
				}
			} else if strings.Contains(contentType, "application/vnd.kubernetes.protobuf") {
				codec := serializer.NewCodecFactory(scheme.Scheme)
				decoder := codec.UniversalDeserializer()

				obj, _, err := decoder.Decode(body, nil, &sar)
				if err != nil {
					server.HandleError(w, err, "failed to parse SelfSubjectAccessReview request")
					return
				}

				if sarPtr, ok := obj.(*authorizationv1.SelfSubjectAccessReview); ok {
					sar = *sarPtr
				} else {
					server.HandleError(w, err, "invalid SelfSubjectAccessReview object")
					return
				}
			} else {
				next.ServeHTTP(w, r)
				return
			}

			proxyRequest := request.NewHTTP(r, authTypes, usernameClaimField, writer, ignoredImpersonationGroups, impersonationGroupsRegexp, skipImpersonationReview)
			username, groups, err := proxyRequest.GetUserAndGroups()
			if err != nil {
				server.HandleError(w, err, "cannot retrieve user and groups from request")
				return
			}

			proxyTenants, err := getTenantsFunc(r.Context(), username, groups)
			if err != nil {
				server.HandleError(w, err, "cannot retrieve user tenants")
				return
			}

			if err := selfsubjectaccessreview.HandleSelfSubjectAccessReview(r.Context(), proxyTenants, username, groups, &sar, writer); err != nil {
				server.HandleError(w, err, "failed to process SelfSubjectAccessReview")
				return
			}

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)

			response, err := json.Marshal(sar)
			if err != nil {
				server.HandleError(w, err, "failed to marshal SelfSubjectAccessReview response")
				return
			}

			if _, err := w.Write(response); err != nil {
				log.Error(err, "failed to write response")
			}
		})
	}
}

func isSelfSubjectAccessReviewRequest(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return false
	}

	path := strings.ToLower(r.URL.Path)
	return path == "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" ||
		   strings.HasSuffix(path, "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews")
}