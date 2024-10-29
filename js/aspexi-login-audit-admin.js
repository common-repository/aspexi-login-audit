jQuery(document).ready(function() {
    jQuery('button.block').on('click', function() {
        jQuery('#dialog-block').dialog({
            modal: true,
            buttons: {
                "Yes": function() {
                    window.open(ala.pro_url, '_blank');
                },
                "No": function() {
                    jQuery(this).dialog('close');
                }
            }
        });
    } );

    jQuery('button.export').on('click', function() {
        jQuery('#dialog-export').dialog({
            modal: true,
            buttons: {
                "Yes": function() {
                    window.open(ala.pro_url, '_blank');
                },
                "No": function() {
                    jQuery(this).dialog('close');
                }
            }
        });
    } );

    var tooltip = jQuery('<div class="asp_tooltip"></div>')
        .appendTo('body');

    jQuery('.dashicons-tooltip').on('mouseenter', function() {
        tooltip.html(jQuery(this).data('info'));
        jQuery(this).append(tooltip);
    }).on('mouseleave', function() {
        tooltip.remove();
    });
});
