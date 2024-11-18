#!/bin/bash

# 使用方法: ./security_scan.sh target.com

# エラーハンドリングの強化
set -eo pipefail
trap 'error_handler $? $LINENO $BASH_LINENO "$BASH_COMMAND" $(printf "::%s" ${FUNCNAME[@]:-})' ERR

# グローバル変数の設定部分
DATE=$(date +%Y%m%d_%H%M%S)
BASE_DIR="security_scans"
MAX_PARALLEL_JOBS=2
TIMEOUT=600

# ディレクトリ構造作成関数
create_scan_directories() {
    local target=$1
    local scan_date=$2
    
    # ベースディレクトリ構造
    # security_scans/
    # └── example.com/
    #     └── 20240422_123456/
    #         ├── network/
    #         ├── web/
    #         ├── ssl/
    #         ├── dns/
    #         ├── mail/
    #         ├── misc/
    #         └── scan_log.txt
    
    local target_dir="${BASE_DIR}/${target}"
    RESULT_DIR="${target_dir}/${scan_date}"
    
    # メインディレクトリ作成
    mkdir -p "${RESULT_DIR}"/{network,web,ssl,dns,mail,misc}
    
    # ログファイル設定
    LOG_FILE="${RESULT_DIR}/scan_log.txt"
    
    # 以前のスキャン結果へのシンボリックリンク作成
    if [ -d "${target_dir}" ]; then
        local latest_link="${target_dir}/latest"
        ln -sfn "${scan_date}" "${latest_link}"
    fi
    
    # スキャン履歴の保存
    echo "${scan_date}" >> "${target_dir}/scan_history.txt"
}

manage_old_scans() {
    local target=$1
    local max_scans=5  # 保持する最大スキャン数
    
    local target_dir="${BASE_DIR}/${target}"
    if [ -f "${target_dir}/scan_history.txt" ]; then
        local scan_count=$(wc -l < "${target_dir}/scan_history.txt")
        if [ "$scan_count" -gt "$max_scans" ]; then
            local scans_to_remove=$((scan_count - max_scans))
            while IFS= read -r old_scan; do
                rm -rf "${target_dir}/${old_scan}"
                log_message "INFO" "古いスキャン結果を削除: ${old_scan}"
                scans_to_remove=$((scans_to_remove - 1))
                [ "$scans_to_remove" -eq 0 ] && break
            done < "${target_dir}/scan_history.txt"
            # 履歴ファイルの更新
            tail -n "$max_scans" "${target_dir}/scan_history.txt" > "${target_dir}/scan_history.txt.tmp"
            mv "${target_dir}/scan_history.txt.tmp" "${target_dir}/scan_history.txt"
        fi
    fi
}

create_scan_summary() {
    local target=$1
    local scan_date=$2
    
    {
        echo "=== スキャン要約 ==="
        echo "ターゲット: ${target}"
        echo "スキャン日時: ${scan_date}"
        echo "HTTP状態: ${HTTP_CODE} (${HTTP_STATUS})"
        echo "HTTPS状態: ${HTTPS_CODE} (${HTTPS_STATUS})"
        echo
        echo "=== 検出された主な問題 ==="
        # 各結果ファイルから重要な情報を抽出
        if [ -f "${RESULT_DIR}/network/nmap_results.txt" ]; then
            echo "## オープンポート"
            grep "open" "${RESULT_DIR}/network/nmap_results.txt" || echo "なし"
        fi
        if [ -f "${RESULT_DIR}/ssl/testssl_results.txt" ]; then
            echo "## SSL/TLS の問題"
            grep -i "vulnerable\|weak" "${RESULT_DIR}/ssl/testssl_results.txt" || echo "なし"
        fi
        if [ -f "${RESULT_DIR}/web/nikto_results.txt" ]; then
            echo "## Web脆弱性"
            grep -i "warning\|vulnerable" "${RESULT_DIR}/web/nikto_results.txt" || echo "なし"
        fi
    } > "${RESULT_DIR}/scan_summary.txt"
}

# エラーハンドラー関数
error_handler() {
    local exit_code=$1
    local line_no=$2
    local bash_lineno=$3
    local last_command=$4
    local func_trace=$5
    echo "Error occurred in:"
    echo "  Exit code: $exit_code"
    echo "  Command  : $last_command"
    echo "  Line     : $line_no"
    echo "  Function : $func_trace"
    cleanup
    exit $exit_code
}

# クリーンアップ関数
cleanup() {
    echo "クリーンアップを実行中..."
    # 実行中のプロセスを終了
    jobs -p | xargs -r kill -9 2>/dev/null || true
    echo "クリーンアップ完了"
}

# ログ出力関数
log_message() {
    local level=$1
    local message=$2
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [${level}] ${message}" | tee -a "$LOG_FILE"
}

# 引数チェック
if [ $# -ne 1 ]; then
    log_message "ERROR" "使用方法: $0 target.com"
    exit 1
fi

TARGET=$1
RESULT_DIR="security_scan_results_${DATE}"
LOG_FILE="${RESULT_DIR}/scan_log.txt"

# ターゲットの検証
if ! echo "$TARGET" | grep -P "^[a-zA-Z0-9][a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}$" > /dev/null; then
    log_message "ERROR" "無効なターゲット指定: $TARGET"
    exit 1
fi

# ディレクトリ作成
mkdir -p "${RESULT_DIR}"/{network,web,ssl,dns,mail,misc}

# タイムアウト付きコマンド実行関数
run_with_timeout() {
    local cmd=$1
    local logfile=$2
    timeout $TIMEOUT bash -c "$cmd" > "$logfile" 2>&1 || {
        local exit_code=$?
        if [ $exit_code -eq 124 ]; then
            log_message "WARN" "コマンドがタイムアウトしました: $cmd"
        else
            log_message "ERROR" "コマンド実行エラー: $cmd (exit code: $exit_code)"
        fi
    }
}

# メイン処理開始
log_message "INFO" "スキャン開始: $TARGET"

# プロトコルチェック
PROTOCOLS=$(check_protocols "$TARGET")
IFS=':' read -r HTTP_CODE HTTPS_CODE HTTP_STATUS HTTPS_STATUS <<< "$PROTOCOLS"

# HTTPSが利用可能かチェック（200番台または300番台のレスポンス）
is_https_available() {
    local code=$1
    local status=$2
    [[ $status -eq 0 ]] && [[ $code =~ ^[23] ]]
}

# HTTPが利用可能かチェック
is_http_available() {
    local code=$1
    local status=$2
    [[ $status -eq 0 ]] && [[ $code =~ ^[23] ]]
}

# プロトコルチェック関数
check_protocols() {
    local target=$1
    local http_code
    local https_code
    
    log_message "INFO" "プロトコル確認開始"
    
    # HTTP確認
    http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://${target}")
    local http_status=$?
    
    # HTTPS確認
    https_code=$(curl -s -o /dev/null -w "%{http_code}" "https://${target}")
    local https_status=$?
    
    log_message "INFO" "HTTP Status: ${http_code} (${http_status})"
    log_message "INFO" "HTTPS Status: ${https_code} (${https_status})"
    
    # 結果を返す（ステータスコードとcurlの終了コード）
    echo "${http_code}:${https_code}:${http_status}:${https_status}"
}

# 並列実行用の関数
run_parallel_scans() {
    # DNS検査（バックグラウンド実行）
    {
        log_message "INFO" "DNS検査開始"
        {
            echo "=== DNS Records ==="
            dig "$TARGET" ANY
            echo -e "\n=== DNS TXT Records ==="
            dig "$TARGET" TXT
            echo -e "\n=== DNS MX Records ==="
            dig "$TARGET" MX
        } > "${RESULT_DIR}/dns/dns_results.txt" 2>&1
        log_message "INFO" "DNS検査完了"
    } &

    # メールサーバー検査（バックグラウンド実行）
    {
        log_message "INFO" "メールサーバー検査開始"
        run_with_timeout "nmap -p25,465,587 -sV $TARGET" "${RESULT_DIR}/mail/mail_results.txt"
        log_message "INFO" "メールサーバー検査完了"
    } &

    # その他の基本検査（バックグラウンド実行）
    {
        log_message "INFO" "その他の検査開始"
        {
            echo "=== Robots.txt ==="
            curl -s "${TARGET}/robots.txt"
            echo -e "\n=== Sitemap.xml ==="
            curl -s "${TARGET}/sitemap.xml"
            echo -e "\n=== Error Pages ==="
            curl -I "${TARGET}/notexist"
        } > "${RESULT_DIR}/misc/misc_results.txt" 2>&1
        log_message "INFO" "その他の検査完了"
    } &
}

# 重い検査の実行
run_heavy_scans() {
    # nmap（シーケンシャル実行）
    if is_http_available "$HTTP_CODE" "$HTTP_STATUS" || is_https_available "$HTTPS_CODE" "$HTTPS_STATUS"; then
        log_message "INFO" "Nmapスキャン開始"
        run_with_timeout "nmap -sV -sC -p- $TARGET" "${RESULT_DIR}/network/nmap_results.txt"
        log_message "INFO" "Nmapスキャン完了"
    fi

    # SSL/TLS検査（HTTPSが利用可能な場合のみ）
    if is_https_available "$HTTPS_CODE" "$HTTPS_STATUS"; then
        log_message "INFO" "SSL/TLS検査開始"
        run_with_timeout "sslscan --no-colour $TARGET" "${RESULT_DIR}/ssl/sslscan_results.txt"
        run_with_timeout "testssl.sh --quiet --color 0 $TARGET" "${RESULT_DIR}/ssl/testssl_results.txt"
        log_message "INFO" "SSL/TLS検査完了"
    fi

    # Web検査
    if is_http_available "$HTTP_CODE" "$HTTP_STATUS" || is_https_available "$HTTPS_CODE" "$HTTPS_STATUS"; then
        log_message "INFO" "Web検査開始"
        local protocol="http"
        if ! is_http_available "$HTTP_CODE" "$HTTP_STATUS" && is_https_available "$HTTPS_CODE" "$HTTPS_STATUS"; then
            protocol="https"
        fi
        run_with_timeout "nikto -h ${protocol}://$TARGET -nointeractive -Tuning 123" "${RESULT_DIR}/web/nikto_results.txt"
        run_with_timeout "dirb ${protocol}://$TARGET -r -w" "${RESULT_DIR}/web/dirb_results.txt"
        log_message "INFO" "Web検査完了"
    fi
}

# メイン実行フロー
main() {
    # 引数チェック
    if [ $# -ne 1 ]; then
        log_message "ERROR" "使用方法: $0 target.com"
        exit 1
    fi

    TARGET=$1
    
    # ターゲットの検証
    if ! echo "$TARGET" | grep -P "^[a-zA-Z0-9][a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}$" > /dev/null; then
        log_message "ERROR" "無効なターゲット指定: $TARGET"
        exit 1
    fi
    
    # ディレクトリ構造作成
    create_scan_directories "$TARGET" "$DATE"
    
    log_message "INFO" "スキャン開始: $TARGET"

    # プロトコルチェック
    PROTOCOLS=$(check_protocols "$TARGET")
    IFS=':' read -r HTTP_CODE HTTPS_CODE HTTP_STATUS HTTPS_STATUS <<< "$PROTOCOLS"

    # 軽い検査を並列実行
    run_parallel_scans

    # 重い検査を実行
    run_heavy_scans

    # すべてのバックグラウンドジョブの完了を待機
    wait

    # スキャン完了後の処理
    create_scan_summary "$TARGET" "$DATE"
    manage_old_scans "$TARGET"
    
    # 結果の圧縮（ドメインごと）
    log_message "INFO" "結果ファイルの圧縮"
    tar -czf "${RESULT_DIR}.tar.gz" -C "${BASE_DIR}/${TARGET}" "${DATE}"
    
    # 完了メッセージ
    log_message "INFO" "スキャン完了"
    echo "結果は ${RESULT_DIR} に保存されました"
    echo "圧縮ファイル: ${RESULT_DIR}.tar.gz"
    echo "要約ファイル: ${RESULT_DIR}/scan_summary.txt"
}

# スクリプトの実行
main "$@" || {
    error_code=$?
    log_message "ERROR" "スキャン中にエラーが発生しました"
    cleanup
    exit $error_code
}

trap - ERR
exit 0