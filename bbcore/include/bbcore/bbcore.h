/*
 * bbcore — BitBackup core library, flat C ABI.
 *
 * Формат контейнера: bbk/1.  См. docs/ARCHITECTURE.md.
 *
 * ABI-правила:
 *   - все функции возвращают bb_status; отрицательное значение — ошибка;
 *   - библиотека никогда не выделяет память, которую освобождает вызывающий,
 *     кроме объектов с явной парой bb_*_free;
 *   - буферы передаются как (ptr, cap) + out_len; при нехватке места
 *     возвращается BB_ERR_BUFFER_TOO_SMALL и out_len = требуемый размер;
 *   - все строки — UTF-8, завершённые нулём;
 *   - объекты не потокобезопасны; разные объекты можно использовать
 *     из разных потоков одновременно.
 */

#ifndef BBCORE_H
#define BBCORE_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#  if defined(BBCORE_STATIC)
#    define BB_API
#  elif defined(BBCORE_BUILD)
#    define BB_API __declspec(dllexport)
#  else
#    define BB_API __declspec(dllimport)
#  endif
#  define BB_CALL __cdecl
#else
#  define BB_API __attribute__((visibility("default")))
#  define BB_CALL
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Константы формата                                                   */
/* ------------------------------------------------------------------ */

#define BB_FORMAT_VERSION      1
#define BB_SUITE_ID            1

#define BB_ID_LEN             32   /* identity_id                      */
#define BB_NAME_LEN           32   /* object_name (сырые байты)        */
#define BB_HASH_LEN           32   /* BLAKE3 / merkle узел             */
#define BB_KEY_LEN            32   /* K_file, K_shard, K_meta          */
#define BB_NONCE_LEN          12   /* AES-GCM-SIV                      */
#define BB_TAG_LEN            16
#define BB_INSTANCE_ID_LEN    32   /* file_instance_id                 */
#define BB_ROOT_LABEL_MAX     64   /* root_label, UTF-8 с нулём        */
#define BB_TRANSFORM_ID_LEN    4   /* алгоритм сжатия + параметры      */

/* Размерные классы открытого текста метаданных. Дополнение до класса
 * не даёт хранилищу оценить число чанков по len_metadata. См. §13. */
#define BB_META_CLASS_MIN   4096
#define BB_META_CLASS_MID   8192
#define BB_META_CLASS_MAX  16384

#define BB_B32_LEN(n)      (((n) * 8 + 4) / 5)
#define BB_ID_B32_LEN         52   /* BB_B32_LEN(BB_ID_LEN)            */
#define BB_NAME_B32_LEN       52
#define BB_OBJECT_NAME_MAX   110   /* 52 + 1 + 52 + ".bbk" + NUL       */

#define BB_MAX_CHUNKS       8192   /* data + parity на один файл       */
#define BB_RS_DATA             8
#define BB_RS_PARITY           3

/* Профиль разбиения по умолчанию, байты. */
#define BB_SPLIT_MIN    (1u << 20)
#define BB_SPLIT_AVG    (2u << 20)
#define BB_SPLIT_MAX    (3u << 20)
#define BB_SPLIT_ALIGN  (64u << 10)

/* ------------------------------------------------------------------ */
/* Коды возврата                                                       */
/* ------------------------------------------------------------------ */

typedef enum bb_status {
    BB_OK                     =  0,
    BB_ERR_INVALID_ARG        = -1,
    BB_ERR_BUFFER_TOO_SMALL   = -2,
    BB_ERR_OUT_OF_MEMORY      = -3,
    BB_ERR_UNSUPPORTED        = -4,   /* неизвестный suite или версия  */
    BB_ERR_BAD_MNEMONIC       = -5,
    BB_ERR_BAD_CONTAINER      = -6,   /* magic/длины не сходятся       */
    BB_ERR_DECRYPT_FAILED     = -7,   /* AEAD-тег не сошёлся           */
    BB_ERR_WRONG_IDENTITY     = -8,   /* чанк адресован не нам         */
    BB_ERR_INTEGRITY          = -9,   /* merkle или BLAKE3 не сошлись  */
    BB_ERR_UNRECOVERABLE      = -10,  /* потерь больше, чем parity     */
    BB_ERR_STORAGE            = -11,  /* ошибка backend'а              */
    BB_ERR_IO                 = -12,
    BB_ERR_CANCELLED          = -13,
    BB_ERR_INTERNAL           = -99
} bb_status;

/** Человекочитаемое описание кода. Указатель статический, освобождать не нужно. */
BB_API const char* BB_CALL bb_status_text(bb_status status);

/** Строка версии библиотеки, например "bbcore 0.1.0 (bbk/1)". */
BB_API const char* BB_CALL bb_version(void);

/** Однократная инициализация процесса. Потокобезопасна, идемпотентна. */
BB_API bb_status BB_CALL bb_init(void);

/* ------------------------------------------------------------------ */
/* Мнемоника и identity                                                */
/* ------------------------------------------------------------------ */

typedef struct bb_identity bb_identity;

/**
 * Сгенерировать новую BIP39-мнемонику из системного CSPRNG.
 * Новые identity всегда используют 24 слова; иное значение отклоняется.
 * Импорт существующих BIP39 mnemonic через bb_identity_open поддерживает
 * стандартные длины 12/15/18/21/24 слова.
 */
BB_API bb_status BB_CALL bb_mnemonic_new(
    unsigned    words,
    char*       out,
    size_t      cap,
    size_t*     out_len);

/** Проверить контрольную сумму и словарь. */
BB_API bb_status BB_CALL bb_mnemonic_validate(const char* mnemonic);

/**
 * Вывести identity с заданным индексом.
 * passphrase может быть NULL (эквивалент пустой строки).
 */
BB_API bb_status BB_CALL bb_identity_open(
    const char*     mnemonic,
    const char*     passphrase,
    uint32_t        index,
    bb_identity**   out_identity);

/**
 * Открыть identity только по публичным ключам — для адресации файлов
 * другому человеку (§26). Расшифровывать такой identity не может.
 */
BB_API bb_status BB_CALL bb_identity_open_public(
    const uint8_t*  public_blob,
    size_t          public_len,
    bb_identity**   out_identity);

BB_API void BB_CALL bb_identity_free(bb_identity* identity);

/** Сырые 32 байта identity_id. */
BB_API bb_status BB_CALL bb_identity_id(
    const bb_identity*  identity,
    uint8_t             out[BB_ID_LEN]);

/** identity_id в base32 lowercase, 52 символа + NUL. */
BB_API bb_status BB_CALL bb_identity_id_text(
    const bb_identity*  identity,
    char*               out,
    size_t              cap);

/** Экспорт публичных ключей (ML-KEM, X25519, ML-DSA) для передачи файлов. */
BB_API bb_status BB_CALL bb_identity_export_public(
    const bb_identity*  identity,
    uint8_t*            out,
    size_t              cap,
    size_t*             out_len);

/** true, если identity содержит приватные ключи. */
BB_API int BB_CALL bb_identity_has_private(const bb_identity* identity);

/* ------------------------------------------------------------------ */
/* Storage backend — реализуется вызывающей стороной                   */
/* ------------------------------------------------------------------ */

/**
 * Приёмник байтов. Возврат 0 — продолжать, отрицательное — прервать.
 * Библиотека вызывает sink многократно с последовательными кусками.
 */
typedef int (BB_CALL *bb_sink_fn)(void* user, const uint8_t* data, size_t len);

/**
 * Источник байтов. Записывает не более cap байт, возвращает число
 * записанных; 0 — конец потока, отрицательное — ошибка.
 */
typedef int64_t (BB_CALL *bb_source_fn)(void* user, uint8_t* buf, size_t cap);

typedef struct bb_object_info {
    char        name[BB_OBJECT_NAME_MAX];
    uint64_t    size;
    int64_t     mtime;          /* unix seconds, -1 если неизвестно */
} bb_object_info;

/**
 * Таблица методов хранилища. Все методы возвращают bb_status.
 * Указатель user передаётся обратно без изменений.
 */
typedef struct bb_storage_vtable {
    uint32_t    struct_size;    /* = sizeof(bb_storage_vtable), для ABI */

    bb_status (BB_CALL *put)(
        void* user, const char* name,
        bb_source_fn source, void* source_user, uint64_t total_size);

    bb_status (BB_CALL *get)(
        void* user, const char* name,
        bb_sink_fn sink, void* sink_user);

    bb_status (BB_CALL *get_range)(
        void* user, const char* name,
        uint64_t offset, uint64_t length,
        bb_sink_fn sink, void* sink_user);

    /* out_exists: 0 или 1 */
    bb_status (BB_CALL *exists)(
        void* user, const char* name, int* out_exists);

    /* Вызывает callback на каждый объект; возврат callback != 0 прерывает. */
    bb_status (BB_CALL *list)(
        void* user, const char* identity_prefix,
        int (BB_CALL *cb)(void* cb_user, const bb_object_info* info),
        void* cb_user);

    bb_status (BB_CALL *remove)(
        void* user, const char* name);
} bb_storage_vtable;

typedef struct bb_storage {
    const bb_storage_vtable*    vtable;
    void*                       user;
} bb_storage;

/* Встроенные backend'ы. Освобождаются через bb_storage_close. */
BB_API bb_status BB_CALL bb_storage_open_local(
    const char* root_path, bb_storage** out_storage);

BB_API void BB_CALL bb_storage_close(bb_storage* storage);

/* ------------------------------------------------------------------ */
/* Прогресс и отмена                                                   */
/* ------------------------------------------------------------------ */

typedef enum bb_phase {
    BB_PHASE_HASH       = 1,
    BB_PHASE_COMPRESS   = 2,
    BB_PHASE_ENCODE     = 3,
    BB_PHASE_UPLOAD     = 4,
    BB_PHASE_DOWNLOAD   = 5,
    BB_PHASE_DECODE     = 6,
    BB_PHASE_VERIFY     = 7
} bb_phase;

typedef struct bb_progress {
    bb_phase    phase;
    uint64_t    done;
    uint64_t    total;          /* 0 если неизвестно */
    uint32_t    chunk_index;
    uint32_t    chunk_count;
} bb_progress;

/** Возврат != 0 отменяет операцию (BB_ERR_CANCELLED). */
typedef int (BB_CALL *bb_progress_fn)(void* user, const bb_progress* p);

/* ------------------------------------------------------------------ */
/* Индекс сессии                                                       */
/*                                                                     */
/* Хранилище нельзя использовать, пока оно не проиндексировано:         */
/* частично скачано, расшифровано и разобрано по версиям файлов.        */
/* Без этого клиент не знает, что там уже лежит, какие объекты          */
/* принадлежали прошлой версии и цел ли комплект — и вместо инкремента  */
/* получится свалка из дубликатов и сирот.                             */
/*                                                                     */
/* Инвариант выражен в типах: backup и restore принимают bb_index, а не */
/* bb_storage. Получить bb_index можно только через bb_index_build.     */
/*                                                                     */
/* Индекс живёт в памяти и уничтожается вместе с сессией. На диск он не */
/* пишется и в хранилище не кешируется. См. ARCHITECTURE.md §22, §23.   */
/* ------------------------------------------------------------------ */

typedef struct bb_index bb_index;

/* Полный API индекса объявлен ниже, после bb_chunk_info. */

/* ------------------------------------------------------------------ */
/* Backup                                                              */
/* ------------------------------------------------------------------ */

typedef enum bb_compression {
    BB_COMPRESSION_AUTO = 0,    /* эвристика по расширению и пробе */
    BB_COMPRESSION_NONE = 1,
    BB_COMPRESSION_ZSTD = 2
} bb_compression;

typedef struct bb_backup_options {
    uint32_t        struct_size;

    bb_compression  compression;
    int             zstd_level;         /* 0 → значение по умолчанию (3) */

    /*
     * Ярлык наблюдаемого корня: "Documents", "Work", "Photos".
     * Вместе с relative_path задаёт file_instance_id.
     *
     * Именно ярлык, а НЕ путь и не буква диска: перенос папки с D:\Work
     * на E:\Work при том же ярлыке не переписывает архив. Ярлыки, уже
     * встречающиеся в архиве, перечисляет bb_index_root_labels. См. §6.
     */
    const char*     root_label;

    /*
     * Точные параметры обработки предыдущей версии, если она была.
     * Нули — взять из индекса, а если версии там нет, выбрать по эвристике.
     * Ненулевое значение переопределяет compression/zstd_level: смена
     * transform_id меняет file_id и вызывает полную перезаливку. См. §7.
     */
    uint8_t         transform_id[BB_TRANSFORM_ID_LEN];

    /*
     * 1 — писать все shards stripe одной длиной. Скрывает, какие объекты
     * являются parity, ценой роста объёма с ~1.38x до ~1.91x. См. §28.
     */
    int             pad_shards;

    uint32_t        rs_data;            /* 0 → BB_RS_DATA   */
    uint32_t        rs_parity;          /* 0 → BB_RS_PARITY */

    uint32_t        split_min;          /* 0 → значения по умолчанию */
    uint32_t        split_avg;
    uint32_t        split_max;
    uint32_t        split_align;

    /* Записать хотя бы в столько хранилищ, иначе ошибка. 0 → во все. */
    uint32_t        min_successful_storages;

    const char*     temp_dir;           /* NULL → системный */
} bb_backup_options;

BB_API void BB_CALL bb_backup_options_init(bb_backup_options* options);

typedef struct bb_backup_result {
    uint32_t    struct_size;

    uint8_t     file_id[BB_HASH_LEN];
    uint8_t     content_hash[BB_HASH_LEN];
    uint8_t     merkle_root[BB_HASH_LEN];

    /* Выведены библиотекой; полезны для отчётов и группировки версий.
     * Сохранять их на устройстве не нужно и не следует — см. §22. */
    uint8_t     file_instance_id[BB_INSTANCE_ID_LEN];
    uint8_t     transform_id[BB_TRANSFORM_ID_LEN];

    uint64_t    plain_size;
    uint64_t    stored_size;        /* после сжатия */
    uint64_t    uploaded_bytes;

    uint32_t    chunk_count;
    uint32_t    chunks_skipped;     /* уже присутствовали в хранилище */
} bb_backup_result;

/**
 * Забэкапить один файл.
 *
 * relative_path — путь, который будет записан в метаданные и использован
 * при восстановлении; source_path — откуда читать прямо сейчас.
 *
 * Принимает bb_index, а не bb_storage: заливать в непроиндексированное
 * хранилище нельзя (§23). Индекс же задаёт и набор целевых хранилищ —
 * тех, по которым он построен.
 */
BB_API bb_status BB_CALL bb_backup_file(
    bb_index*                   index,
    const char*                 source_path,
    const char*                 relative_path,
    const bb_backup_options*    options,
    bb_progress_fn              progress,
    void*                       progress_user,
    bb_backup_result*           out_result);

/* ------------------------------------------------------------------ */
/* Чтение метаданных чанка                                             */
/* ------------------------------------------------------------------ */

/**
 * Сколько байт от начала объекта достаточно прочитать, чтобы получить
 * метаданные без загрузки shard core. Значение верхнее, безопасное.
 *
 * Открытого заголовка у чанка нет: в объекте нет ни одного байта открытого
 * текста (§16). Границы находятся пробным расшифрованием, поэтому «прочитать
 * заголовок» здесь означает «прочитать префикс и область метаданных».
 */
BB_API size_t BB_CALL bb_header_probe_size(void);

typedef struct bb_chunk_info {
    uint32_t    struct_size;

    uint8_t     identity_id[BB_ID_LEN];
    uint8_t     file_id[BB_HASH_LEN];
    uint8_t     file_instance_id[BB_INSTANCE_ID_LEN];
    uint8_t     content_hash[BB_HASH_LEN];
    uint8_t     merkle_root[BB_HASH_LEN];

    char        file_name[512];
    char        file_path[1024];

    uint64_t    plain_size;
    uint64_t    stored_size;
    int64_t     created;
    int64_t     modified;
    uint32_t    attributes;

    /* Точные параметры обработки этой версии файла. Обязаны быть
     * переиспользованы при следующем backup того же file_instance_id,
     * иначе меняется file_id и весь архив уезжает. См. §6, §7. */
    uint8_t     transform_id[BB_TRANSFORM_ID_LEN];
    bb_compression compression;

    int         pad_shards;     /* 1 — все shards в stripe равной длины */

    uint32_t    rs_data;
    uint32_t    rs_parity;
    uint32_t    chunk_count;

    uint32_t    self_index;
    uint32_t    self_stripe;
    uint32_t    self_position;
    int         self_is_parity;

    int         signed_transfer;                    /* 1 если есть ML-DSA */
    uint8_t     sender_identity_id[BB_ID_LEN];      /* валидно при signed */
} bb_chunk_info;

/**
 * Разобрать чанк. blob может быть усечён до bb_header_probe_size() байт.
 *
 * object_name — полное имя объекта "<identity>.<name>.bbk", под которым он
 * лежит в хранилище. Оно обязательно: имя входит в AAD метаданных (§14), и без
 * него чанк не вскрыть. У вызывающего оно есть всегда — именно по нему объект
 * и был получен.
 *
 * object_size — полный размер объекта в хранилище. Если blob не усечён, это
 * blob_len. Нужен, чтобы вычислить длину shard core: открытых длин у чанка нет.
 */
BB_API bb_status BB_CALL bb_chunk_inspect(
    const bb_identity*  identity,
    const char*         object_name,
    const uint8_t*      blob,
    size_t              blob_len,
    uint64_t            object_size,
    bb_chunk_info*      out_info);

/**
 * Вывести имена всех объектов файла. Требует identity с приватным ключом
 * и любой чанк этого файла.
 *
 * out_names — буфер под chunk_count строк по BB_OBJECT_NAME_MAX байт.
 */
BB_API bb_status BB_CALL bb_chunk_object_names(
    const bb_identity*  identity,
    const char*         object_name,
    const uint8_t*      blob,
    size_t              blob_len,
    uint64_t            object_size,
    char*               out_names,
    size_t              out_names_cap,
    uint32_t*           out_count);

/* ------------------------------------------------------------------ */
/* Индекс сессии — полный API                                          */
/* ------------------------------------------------------------------ */

/**
 * Построить индекс по одному или нескольким хранилищам.
 *
 * Операция дорогая: один range-запрос и одна decapsulation на каждую
 * версию файла. Обязательно передавайте progress и поддерживайте отмену.
 *
 * Индекс пригоден к работе по мере наполнения не полностью: пока построение
 * не завершено, отсутствие файла в индексе ничего не значит, поэтому backup
 * до конца операции запрещён.
 */
BB_API bb_status BB_CALL bb_index_build(
    const bb_identity*  identity,
    bb_storage* const*  storages,
    size_t              storage_count,
    bb_progress_fn      progress,
    void*               progress_user,
    bb_index**          out_index);

/** Уничтожает индекс и затирает его содержимое. */
BB_API void BB_CALL bb_index_free(bb_index* index);

/** Число версий файлов в индексе. */
BB_API size_t BB_CALL bb_index_version_count(const bb_index* index);

/**
 * Перечислить root_label, встречающиеся в архиве, чтобы предложить
 * пользователю сопоставить их с локальными папками. Ярлыки нигде не
 * хранятся — они восстанавливаются из путей в метаданных.
 *
 * out_labels — буфер под count строк по BB_ROOT_LABEL_MAX байт.
 */
BB_API bb_status BB_CALL bb_index_root_labels(
    const bb_index* index,
    char*           out_labels,
    size_t          out_labels_cap,
    size_t*         out_count);

/**
 * Найти версии файла по ярлыку и относительному пути, новейшая первой.
 * Возвращает BB_OK и out_count = 0, если такого файла в архиве нет.
 */
BB_API bb_status BB_CALL bb_index_find(
    const bb_index* index,
    const char*     root_label,
    const char*     relative_path,
    bb_chunk_info*  out_versions,
    size_t          versions_cap,
    size_t*         out_count);

/**
 * Найти объекты, не относящиеся ни к одной версии из индекса, — сироты
 * после переименований и оборванных загрузок. Кандидаты на удаление
 * в retention-проходе (§27).
 */
BB_API bb_status BB_CALL bb_index_orphans(
    const bb_index* index,
    char*           out_names,
    size_t          out_names_cap,
    size_t*         out_count);

/* ------------------------------------------------------------------ */
/* Restore                                                             */
/* ------------------------------------------------------------------ */

typedef struct bb_restore_options {
    uint32_t    struct_size;

    int         overwrite;              /* 0 — не перезаписывать          */
    int         restore_timestamps;     /* 1 по умолчанию                 */
    int         restore_attributes;     /* 1 по умолчанию                 */
    int         verify_only;            /* только проверить, не писать    */
    const char* temp_dir;
} bb_restore_options;

BB_API void BB_CALL bb_restore_options_init(bb_restore_options* options);

typedef struct bb_restore_result {
    uint32_t    struct_size;

    uint64_t    plain_size;
    uint32_t    chunks_found;
    uint32_t    chunks_missing;
    uint32_t    chunks_repaired;    /* восстановлено через Reed–Solomon */
    int         hash_verified;
} bb_restore_result;

/**
 * Восстановить файл, стартуя с любого его чанка.
 *
 * seed_blob — содержимое одного .bbk (достаточно префикса, если
 * остальные чанки доступны в storages).
 *
 * Единственная операция, не требующая индекса: имена всех чанков
 * выводятся из K_file, полученного прямо из этого контейнера. Работает
 * даже с тем хранилищем, которое клиент видит впервые.
 */
BB_API bb_status BB_CALL bb_restore_from_chunk(
    const bb_identity*          identity,
    const uint8_t*              seed_blob,
    size_t                      seed_blob_len,
    bb_storage* const*          storages,
    size_t                      storage_count,
    const char*                 destination_path,
    const bb_restore_options*   options,
    bb_progress_fn              progress,
    void*                       progress_user,
    bb_restore_result*          out_result);

/* ------------------------------------------------------------------ */
/* Утилиты                                                             */
/* ------------------------------------------------------------------ */

/** base32 lowercase без padding (RFC 4648). */
BB_API bb_status BB_CALL bb_base32_encode(
    const uint8_t* data, size_t len, char* out, size_t cap, size_t* out_len);

BB_API bb_status BB_CALL bb_base32_decode(
    const char* text, uint8_t* out, size_t cap, size_t* out_len);

/** Собрать имя объекта "<identity>.<name>.bbk". */
BB_API bb_status BB_CALL bb_object_name_format(
    const uint8_t identity_id[BB_ID_LEN],
    const uint8_t object_name[BB_NAME_LEN],
    char*         out,
    size_t        cap);

/** Разобрать имя объекта обратно. Любой out-параметр может быть NULL. */
BB_API bb_status BB_CALL bb_object_name_parse(
    const char* text,
    uint8_t     out_identity_id[BB_ID_LEN],
    uint8_t     out_object_name[BB_NAME_LEN]);

/** Затереть буфер так, чтобы компилятор не выбросил операцию. */
BB_API void BB_CALL bb_secure_zero(void* data, size_t len);

/**
 * Запретить выгрузку страниц на диск (VirtualLock / mlock).
 *
 * Обязательно для ключевого материала и буферов расшифрованных метаданных:
 * без этого обещание «на устройстве нет открытых данных» не выполняется,
 * потому что ОС может записать их в pagefile. См. §22.
 *
 * Возвращает BB_ERR_UNSUPPORTED, если лимит заблокированной памяти исчерпан;
 * вызывающий обязан это обработать, а не игнорировать.
 */
BB_API bb_status BB_CALL bb_secure_lock(void* data, size_t len);

/** Затирает буфер и снимает блокировку. */
BB_API void BB_CALL bb_secure_unlock(void* data, size_t len);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* BBCORE_H */
