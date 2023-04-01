#!/usr/bin/env groovy

/* `buildPlugin` step provided by: https://github.com/jenkins-infra/pipeline-library */
buildPlugin(
  // Container agents start faster and are easier to administer
  useContainerAgent: true,
  // Show failures on all configurations
  failFast: false,
  // Test Java 11 with default Jenkins version, Java 17 with more recent LTS
  configurations: [
    [platform: 'linux',   jdk: '17', jenkins: '2.387.1'],
    [platform: 'windows', jdk: '11']
  ]
)
