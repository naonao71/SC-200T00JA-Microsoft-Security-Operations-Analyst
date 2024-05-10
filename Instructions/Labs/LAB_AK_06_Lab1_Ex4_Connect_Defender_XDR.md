---
lab:
    title: 'Exercise 4 - Connect Defender XDR to Microsoft Sentinel using data connectors'
    module: 'Learning Path 6 - Connect logs to Microsoft Sentinel'
---

# ラーニング パス 6 - ラボ 1 - 演習 4 - データ コネクタを使用して Defender XDR を Microsoft Sentinel に接続する

## ラボのシナリオ

あなたは、Microsoft Defender XDR と Microsoft Sentinel の両方をデプロイした会社で働いているセキュリティ運用アナリストです。Microsoft Sentinel を Defender XDR に接続する統合セキュリティ運用プラットフォームを準備する必要があります。次の手順では、Defender XDR コンテンツ ハブ ソリューションをインストールし、Defender XDR データ コネクタを Microsoft Sentinel にデプロイします。

###タスク 1: Defender XDR を接続する

このタスクでは、Microsoft Defender XDR コネクタをデプロイします。

1. 管理者として WIN1 仮想マシンにログインします。パスワードは **Pa55w.rd** です。  

1. Microsoft Edgeブラウザーで Azure portal　(https://portal.azure.com) に移動します。

1. **サインイン**ダイアログボックスで、ラボ ホスティング プロバイダーから提供された**テナントの電子メール**アカウントをコピーして貼り付け、「**次へ**」を選択します。

1. **パスワードの入力**ダイアログ ボックスで、ラボ ホスティング プロバイダーから提供された**テナントパスワード** をコピーして貼り付け、「**サインイン**」を選択します。

1. Azure ポータルの検索バーに 「**Sentinel**」 と入力し、「**Microsoft Sentinel**」 を選択します。

1. 前のラボで作成した Microsoft Sentinel ワークスペースを選択します。

1. Microsoft Sentinel の左側のメニューで、 [コンテンツ管理] セクションまで下にスクロールし、 [コンテンツ ハブ] を選択します。

1. コンテンツ ハブで、Microsoft Defender XDR ソリューションを検索し、一覧から選択します。
   
1. Microsoft Defender XDR ソリューションの詳細ページで、 [インストール] を選択します。

1. インストールが完了したら、Microsoft Defender XDR ソリューションを検索して選択します。

1. Microsoft Defender XDR ソリューションの詳細ページで、 [管理] を選択します

>**Note:** Microsoft Defender XDR ソリューションでは、Microsoft Defender XDR データ コネクタ、ハンティング クエリ、ブック、分析ルールがインストールされます。

1. **Microsoft Defender XDR** データ コネクタのチェック ボックスをオンにし、[**コネクタ ページを開く**] を選択します。

1. [構成] セクションの [手順] タブで、[**これらの製品の Microsoft インシデント作成ルールをすべてオフにすることをお勧めします。**　のチェック ボックスの選択を解除します。 [**インシデントとアラートを接続する**] ボタンを選択します。

1. 接続が成功したことを示すメッセージが表示されます。
   
## これでラボは終了です
