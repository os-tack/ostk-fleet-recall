//! Kubernetes adapter with a native shipper sidecar and no workload SA token.
use std::{collections::BTreeMap, path::PathBuf};

use anyhow::ensure;
use async_trait::async_trait;
use serde_json::{Value, json};

use super::{SandboxBackend, SandboxHandle, SandboxSpecV1, process};

pub struct KubernetesBackend {
    pub(crate) program: PathBuf,
}
impl Default for KubernetesBackend {
    fn default() -> Self {
        Self {
            program: "kubectl".into(),
        }
    }
}

fn secret(spec: &SandboxSpecV1, suffix: &str, env: &BTreeMap<String, String>) -> Value {
    let data: BTreeMap<_, _> = env
        .iter()
        .map(|(key, value)| (key, crate::encoding::base64::encode(value.as_bytes())))
        .collect();
    json!({"apiVersion":"v1","kind":"Secret","metadata":{"name":format!("{}-{suffix}",spec.name),"namespace":spec.namespace,"labels":{"app.kubernetes.io/managed-by":"fleet-recall-launch"}},"type":"Opaque","immutable":true,"data":data})
}

pub fn manifest(spec: &SandboxSpecV1) -> Value {
    let security = json!({"allowPrivilegeEscalation":false,"readOnlyRootFilesystem":true,"capabilities":{"drop":["ALL"]}});
    let mut pod_spec = json!({
        "restartPolicy":"Never", "enableServiceLinks":false, "automountServiceAccountToken":false,
        "terminationGracePeriodSeconds":180,
        "securityContext":{"runAsNonRoot":true,"runAsUser":10001,"runAsGroup":10001,"fsGroup":10001,"seccompProfile":{"type":"RuntimeDefault"}},
        "volumes":[{"name":"transcripts","emptyDir":{"sizeLimit":"1Gi"}},{"name":"agent-home","emptyDir":{"medium":"Memory","sizeLimit":"256Mi"}},{"name":"tmp","emptyDir":{"medium":"Memory","sizeLimit":"64Mi"}}],
        // Native sidecars terminate after the agent and receive SIGTERM for a
        // final shipper flush. No shared PID namespace or token volume.
        "initContainers":[{"name":"shipper","restartPolicy":"Always","image":spec.shipper_image,
            "command":["/usr/local/bin/ostk-fleet-recall"],"args":spec.shipper_args,
            "envFrom":[{"secretRef":{"name":format!("{}-shipper-env",spec.name)}}],
            "securityContext":security,"resources":{"requests":{"cpu":"50m","memory":"32Mi"},"limits":{"cpu":"500m","memory":"128Mi"}},
            "volumeMounts":[{"name":"transcripts","mountPath":"/transcripts","readOnly":true}]}],
        "containers":[{"name":"agent","image":spec.image,
            "envFrom":[{"secretRef":{"name":format!("{}-agent-env",spec.name)}}],
            "securityContext":security,"resources":{"requests":{"cpu":"100m","memory":"256Mi"},"limits":{"cpu":"2","memory":"1Gi"}},
            "volumeMounts":[{"name":"transcripts","mountPath":"/transcripts"},{"name":"agent-home","mountPath":"/home/sandbox"},{"name":"tmp","mountPath":"/tmp"}]}]
    });
    if let Some(class) = &spec.runtime_class {
        pod_spec["runtimeClassName"] = json!(class);
    }
    json!({"apiVersion":"v1","kind":"List","items":[secret(spec,"agent-env",&spec.env),secret(spec,"shipper-env",&spec.shipper_env),{"apiVersion":"v1","kind":"Pod","metadata":{"name":spec.name,"namespace":spec.namespace,"labels":{"app.kubernetes.io/managed-by":"fleet-recall-launch"}},"spec":pod_spec}]})
}

#[async_trait]
impl SandboxBackend for KubernetesBackend {
    async fn create(&self, spec: &SandboxSpecV1) -> anyhow::Result<SandboxHandle> {
        spec.validate()?;
        let args = [
            "apply",
            "--server-side",
            "--field-manager=fleet-recall-launch",
            "--namespace",
            &spec.namespace,
            "-f",
            "-",
        ]
        .map(str::to_owned);
        process::checked(
            &self.program,
            &args,
            Some(serde_json::to_vec(&manifest(spec))?),
        )
        .await?;
        Ok(SandboxHandle {
            name: spec.name.clone(),
            namespace: spec.namespace.clone(),
            transcript_volume: spec.transcript_volume.clone(),
        })
    }

    async fn destroy(&self, handle: &SandboxHandle) -> anyhow::Result<()> {
        handle.validate()?;
        let pod_args = [
            "delete",
            "pod",
            &handle.name,
            "--namespace",
            &handle.namespace,
            "--ignore-not-found=true",
            "--wait=true",
            "--timeout=210s",
        ]
        .map(str::to_owned);
        let pod = process::checked(&self.program, &pod_args, None).await;
        let agent = format!("{}-agent-env", handle.name);
        let shipper = format!("{}-shipper-env", handle.name);
        let secrets = [
            "delete",
            "secret",
            &agent,
            &shipper,
            "--namespace",
            &handle.namespace,
            "--ignore-not-found=true",
            "--wait=true",
            "--timeout=10s",
        ]
        .map(str::to_owned);
        let secrets = process::checked(&self.program, &secrets, None).await;
        ensure!(
            pod.is_ok() && secrets.is_ok(),
            "could not clean up all Kubernetes launch resources"
        );
        Ok(())
    }
}
