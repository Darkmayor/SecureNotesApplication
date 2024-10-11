package com.securenote.securenotes.Services.impl;

import com.securenote.securenotes.Entities.AuditLog;
import com.securenote.securenotes.Entities.Note;
import com.securenote.securenotes.Repository.AuditLogRepository;
import com.securenote.securenotes.Services.AuditLogService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

import java.util.List;


@Service
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class AuditLogServiceImpl implements AuditLogService {

   private final AuditLogRepository auditLogRepository;

    @Override
    public void logNoteCreation(String username, Note note){
        AuditLog auditLog = new AuditLog();
        auditLog.setUsername(username);
        auditLog.setNoteContent(note.getContent());
        auditLog.setNoteId(note.getId());
        auditLog.setDateTime(LocalDateTime.now());
        auditLog.setAction("CREATE");
        auditLogRepository.save(auditLog);
    }

    @Override
    public void logNoteDeletion(String username, Long noteId) {
        AuditLog log = new AuditLog();
        log.setAction("DELETED");
        log.setUsername(username);
        log.setNoteId(noteId);
        log.setDateTime(LocalDateTime.now());
        auditLogRepository.save(log);
    }

    @Override
    public void logNoteUpdation(String username, Note note){
        AuditLog auditLog = new AuditLog();
        auditLog.setUsername(username);
        auditLog.setNoteContent(note.getContent());
        auditLog.setNoteId(note.getId());
        auditLog.setDateTime(LocalDateTime.now());
        auditLog.setAction("UPDATE");
        auditLogRepository.save(auditLog);
    }

    @Override
    public List<AuditLog> getAllAuditLogs(){
        return auditLogRepository.findAll();
    }
    @Override
    public List<AuditLog> getAuditLogForNote(Long noteId){
        return auditLogRepository.findByNoteId(noteId);
    }

}
