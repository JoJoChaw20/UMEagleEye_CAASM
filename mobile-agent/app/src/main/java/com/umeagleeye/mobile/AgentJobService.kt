package com.umeagleeye.mobile

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent

/** Runs a round of the agent every 15 minutes (Android's shortest period for background work)
 *  when the phone has a network, also after a restart. Android defers it while the phone dozes
 *  (screen off and still), more so under a phone maker's battery saver unless the app is exempt. */
class AgentJobService : JobService() {
    override fun onStartJob(params: JobParameters): Boolean {
        Thread {
            Store(applicationContext).lastBackgroundAt = System.currentTimeMillis()
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

        fun isScheduled(context: Context): Boolean =
            context.getSystemService(JobScheduler::class.java)?.getPendingJob(JOB_ID) != null

        /** Schedule the round when connected and it is not there (an update, or a phone maker's
         *  cleaner, can drop it); an existing one is left alone so its timing is not reset. */
        fun ensureScheduled(context: Context) {
            if (Store(context).connected && !isScheduled(context)) schedule(context)
        }

        fun cancel(context: Context) {
            context.getSystemService(JobScheduler::class.java)?.cancel(JOB_ID)
        }
    }
}

/** After the app is updated (a new APK installed over it): put the 15-minute round back. */
class UpdateReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_MY_PACKAGE_REPLACED) AgentJobService.ensureScheduled(context)
    }
}
