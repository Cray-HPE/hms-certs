@Library('dst-shared@master') _

dockerBuildPipeline {
        githubPushRepo = "Cray-HPE/hms-certs"
        repository = "cray"
        imagePrefix = "hms"
        app = "hms-certs"
        name = "hms-certs"
        description = "Cray HMS TLS cert management library package."
        dockerfile = "Dockerfile"
        slackNotification = ["", "", false, false, true, true]
        product = "internal"
}
