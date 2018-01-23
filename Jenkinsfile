#!groovy
//from global library https://github.com/jenkins-infra/pipeline-library
properties([
    pipelineTriggers([
        issueCommentTrigger('.*test this please.*')
    ])
])
buildPlugin(platforms: ['linux'])
