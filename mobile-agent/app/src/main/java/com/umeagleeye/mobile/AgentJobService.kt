package com.umeagleeye.mobile

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context

/** Runs a round of the agent every 15 minutes (Android's shortest period for background work)
 *  when the phone has a network, also after a restart. Android may delay it while the phone sleeps. */
class AgentJobService : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        Thread {
            runCatching { Agent.runOnce(applicationContext) }
            jobFinished(params, false)
        }.start()
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean = true     // try again later

    companion object {
        private const val JOB_ID = 1

        fun schedule(context: Context) {
            val job = JobInfo.Builder(JOB_ID, ComponentName(context, AgentJobService::class.java))
                .setPeriodic(15 * 60 * 1000L)
                .setPersisted(true)
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .build()
            context.getSystemService(JobScheduler::class.java)?.schedule(job)
        }

        fun cancel(context: Context) {
            context.getSystemService(JobScheduler::class.java)?.cancel(JOB_ID)
        }
    }
}
