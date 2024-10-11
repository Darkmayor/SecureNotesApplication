package com.securenote.securenotes.Repository;

import com.securenote.securenotes.Entities.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;


public interface AuditLogRepository extends JpaRepository< AuditLog,Long > {

    List<AuditLog> findByNoteId(Long noteId);
}
