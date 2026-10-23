namespace ScoutWall.Data.Models;

/// <summary>
/// The chat page: the conversation so far, the proposed changes and whether an assistant is available.
/// </summary>
public class ChatPage
{
    public List<ChatMessage> Messages { get; set; } = [];
    public List<PendingChange> Changes { get; set; } = [];
    public AnalystSettings Assistant { get; set; } = new();

    public bool CanProposeChanges => Assistant.Provider == AnalystProvider.Claude;

    public static readonly IReadOnlyList<string> Suggestions =
    [
        "Is my computer safe right now?",
        "What sent data while I was away?",
        "Which apps use the internet the most?",
        "Email me when something serious happens",
        "What does practice mode mean?"
    ];

    public static async Task<ChatPage> Build(DataContext dataContext, long userId)
    {
        return new ChatPage
        {
            Messages = await ChatMessage.GetRecent(dataContext, userId, 40),
            Changes = await PendingChange.GetRecent(dataContext, userId, 20),
            Assistant = await Setting.Load<AnalystSettings>(dataContext)
        };
    }

    /// <summary>
    /// Changes proposed after a message and before the next one, so each card shows under the reply that made it.
    /// </summary>
    public List<PendingChange> ChangesAfter(ChatMessage message, ChatMessage? nextMessage)
    {
        return Changes
            .Where(change => change.CreatedAt >= message.CreatedAt.AddSeconds(-120) && change.CreatedAt <= message.CreatedAt.AddSeconds(1)
                && (nextMessage == null || change.CreatedAt < nextMessage.CreatedAt))
            .OrderBy(change => change.CreatedAt)
            .ToList();
    }
}
