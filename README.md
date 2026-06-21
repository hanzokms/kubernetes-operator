<p align="center">
  <p align="center"><b>Hanzo KMS Kubernetes Operator </b>
</p>
<h4 align="center">
  |
  <a href="https://hanzo.ai/docs/integrations/platforms/kubernetes/overview">Documentation</a> |
  <a href="https://www.hanzo.ai">Website</a> | 
  <a href="https://hanzo.ai/slack">Slack</a>
  |
</h4>

<h4 align="center">
  <a href="https://github.com/Hanzo KMS/kubernetes-operator/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="Hanzo KMS is released under the MIT license." />
  </a>
  <a href="https://github.com/kms/kms/blob/main/CONTRIBUTING.md">
    <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen" alt="PRs welcome!" />
  </a>
  <a href="https://github.com/Hanzo KMS/kms/issues">
    <img src="https://img.shields.io/github/commit-activity/m/kms/kms" alt="git commit activity" />
  </a>
  <a href="https://hanzo.ai/slack">
    <img src="https://img.shields.io/badge/chat-on%20Slack-blueviolet" alt="Slack community channel" />
  </a>
  <a href="https://twitter.com/kms">
    <img src="https://img.shields.io/twitter/follow/kms?label=Follow" alt="Hanzo KMS Twitter" />
  </a>
</h4>

## Introduction

**[Hanzo KMS](https://hanzo.ai)** is the open source secret management platform that teams use to centralize their secrets like API keys, database credentials, and configurations.

The Hanzo KMS Operator is a collection of Kubernetes controllers that streamline how secrets are managed between Hanzo KMS and your Kubernetes cluster. It provides multiple Custom Resource Definitions (CRDs) which enable you to:

- Sync secrets from Hanzo KMS into Kubernetes (`KMSSecret`).
- Push new secrets from Kubernetes to Hanzo KMS (`KMSPushSecret`).
- Manage dynamic secrets and automatically create time-bound leases (`KMSDynamicSecret`).

## Security

Please do not file GitHub issues or post on our public forum for security vulnerabilities, as they are public!

Hanzo KMS takes security issues very seriously. If you have any concerns about Hanzo KMS or believe you have uncovered a vulnerability, please get in touch via the e-mail address security@hanzo.ai. In the message, try to provide a description of the issue and ideally a way of reproducing it. The security team will get back to you as soon as possible.

Note that this security address should be used only for undisclosed vulnerabilities. Please report any security problems to us before disclosing it publicly.
