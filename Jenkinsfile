#!/usr/bin/env groovy
node {
  stage('git checkout') {
    step([$class: 'WsCleanup'])
    final scmVars = checkout(
      [$class: 'GitSCM',
       branches: [[name: '*/temp-cause-slack-notification']],
       doGenerateSubmoduleConfigurations: false,
       extensions: [
        [$class: 'CloneOption', depth: 0, noTags: false, reference: '', shallow: false]],
       userRemoteConfigs: [
         [credentialsId: 'hmrc-githubcom-service-infra-user-and-pat',
          url: 'https://github.com/HMRC/aws-ebs-snapshot-lambda.git']]]
    )
    sh("echo ${scmVars.GIT_BRANCH} | cut -f 2 -d '/' > .git/_branch")
  }
  stage('docker') {
    sh('make ci_docker_build')
  }
  stage('build') {
    sh('make ci_build')
  }
  stage('publish') {
    sh('make ci_publish')
  }
  stage('push tags') {
    try {
    withCredentials(
      [[$class: 'UsernamePasswordMultiBinding',
        credentialsId: 'hmrc-githubcom-service-infra-user-and-pat',
        usernameVariable: 'GIT_USERNAME',
        passwordVariable: 'GIT_PASSWORD'
      ]]
    ) {
      sh("git remote add github https://${env.GIT_USERNAME}:${env.GIT_PASSWORD}@github.com/hmrc/aws-ebs-snapshot-lambda.git")
      sh("git tag `cat .release-version`")
      sh("git push github --tags")
    }
  } finally {
      sh("git remote rm github")
  }
}
}