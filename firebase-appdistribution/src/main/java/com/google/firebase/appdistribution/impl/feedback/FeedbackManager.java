package com.google.firebase.appdistribution.impl.feedback;

import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.Tasks;
import com.google.firebase.appdistribution.impl.FirebaseAppDistributionTesterApiClient;
import com.google.firebase.appdistribution.impl.LogWrapper;

public class FeedbackManager {

  private final FirebaseAppDistributionTesterApiClient testerApiClient;

  public FeedbackManager(
      FirebaseAppDistributionTesterApiClient testerApiClient) {
    this.testerApiClient = testerApiClient;
  }

  public void collectAndSendFeedback() {
    testerApiClient.findRelease()
        .onSuccessTask(releaseName ->
            collectFeedbackText()
                .onSuccessTask(feedbackText ->
                    testerApiClient.createFeedback(releaseName, feedbackText)))
        .onSuccessTask(feedbackName -> testerApiClient.commitFeedback(feedbackName))
        .addOnFailureListener(
            e -> LogWrapper.getInstance().e("LKELLOGG: Failed to submit feedback", e));
  }

  // TODO(lkellogg): Actually prompt and collect feedback
  private Task<String> collectFeedbackText() {
    return Tasks.forResult("This app is cool!");
  }
}
