package com.securenote.securenotes.Services;

import com.securenote.securenotes.Entities.AuditLog;
import com.securenote.securenotes.Entities.Note;

import java.util.List;

public interface AuditLogService {

    public void logNoteCreation(String username, Note note);
    public void logNoteDeletion(String username, Long noteId);
    public void logNoteUpdation(String username, Note note);
    public List<AuditLog> getAllAuditLogs();
    public List<AuditLog> getAuditLogForNote(Long noteId);
}
