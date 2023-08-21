#!/bin/bash

# 将iptables存入git
# git -C /etc/network diff HEAD^ iptables.up.rules
# git -C /etc/network diff <hash> iptables.up.rules

DIR_PATH="/etc/network"
SAVE_PATH="$DIR_PATH/iptables.up.rules"
BACKUP_DIR="$DIR_PATH/backup"
GIT_USER='bot'
GIT_EMAIL='bot@dust.com'

export PATH=$PATH:/usr/sbin:/sbin

replace_counts() {
    iptables-save | sed -e 's/\[.*\]//g' | sed '/^#/d'
}

compare_rules() {
    PROCESSED_RULES=$(replace_counts)
    if [ "$PROCESSED_RULES" != "$(cat $SAVE_PATH 2>/dev/null)" ]; then
        return 1  # 表示有变化
    else
        return 0  # 表示没有变化
    fi
}

save_current_rules() {
    echo "$PROCESSED_RULES" > $SAVE_PATH
}

init_git_repo() {
    if [ ! -d "$DIR_PATH/.git" ]; then
        git -C $DIR_PATH init
        git -C $DIR_PATH config user.name $GIT_USER
        git -C $DIR_PATH config user.email $GIT_EMAIL
        echo "*" > "$DIR_PATH/.gitignore"
        echo "!iptables.up.rules" >> "$DIR_PATH/.gitignore"
    fi
}

backup_with_git() {
    init_git_repo
    git -C $DIR_PATH add iptables.up.rules
    TIMESTAMP=$(date +"%Y-%m-%d %H:%M:%S")
    git -C $DIR_PATH commit -m "Update at $TIMESTAMP"
    echo "Iptables rules have been updated and committed with git."
}

backup_to_backup_dir() {
    if [ ! -d $BACKUP_DIR ]; then
        mkdir -p $BACKUP_DIR
    fi

    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    BACKUP_PATH="$BACKUP_DIR/iptables.up.rules_$TIMESTAMP"
    cp $SAVE_PATH $BACKUP_PATH
    echo "Iptables rules have been saved and previous rules backed up to $BACKUP_PATH."
}

main_backup() {
    backup_with_git

    if compare_rules; then
        echo "No changes detected in iptables rules."
        return
    fi
    save_current_rules
    backup_to_backup_dir
}

main_backup
