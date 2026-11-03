using Serilog;

namespace SimplySec.App.Infrastructure;

/// <summary>
/// Runs slow work (scans, fixes, undo) on the thread pool so the window never freezes (port of
/// ui/workers.py). Every task ends with exactly one callback, result or error, delivered on the
/// UI thread. "Finished" runs from that same delivery, before the result handler, so the busy
/// state always clears, and clears before any result dialog opens.
/// </summary>
public sealed class BackgroundRunner(SynchronizationContext ui)
{
    private readonly HashSet<Task> _running = [];

    /// <summary>Tasks that have not delivered their result yet.</summary>
    public int Running
    {
        get
        {
            lock (_running)
            {
                return _running.Count;
            }
        }
    }

    public Task Run<T>(
        Func<Action<string>, T> work,
        Action<T>? onResult = null,
        Action<string>? onError = null,
        Action<string>? onProgress = null,
        Action? onFinished = null)
    {
        void Progress(string text)
        {
            if (onProgress is not null)
            {
                ui.Post(_ => onProgress(text), null);
            }
        }

        void End(Action deliver, Task self)
        {
            ui.Post(_ =>
            {
                lock (_running)
                {
                    _running.Remove(self);
                }
                try
                {
                    onFinished?.Invoke();
                }
                finally
                {
                    deliver();
                }
            }, null);
        }

        Task? task = null;
        var gate = new TaskCompletionSource();
        task = Task.Run(async () =>
        {
            await gate.Task.ConfigureAwait(false);
            T value;
            try
            {
                value = work(Progress);
            }
            catch (Exception exc)
            {
                Log.Error(exc, "background task failed");
                var message = exc.Message.Length > 0 ? exc.Message : exc.GetType().Name;
                End(() => onError?.Invoke(message), task!);
                return;
            }
            End(() => onResult?.Invoke(value), task!);
        });
        lock (_running)
        {
            _running.Add(task);
        }
        gate.SetResult();
        return task;
    }
}
